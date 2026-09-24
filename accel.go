package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
)

// accelChunkSize 是每次限速等待的最大块大小
const accelChunkSize = 256 << 10

// serveAccel 处理 X-Accel-Redirect：由 http.ServeContent 负责 Range / 多段 Range / If-Range /
// If-None-Match / If-Modified-Since / HEAD / 416，经 throttledWriter 限速。
// 标准库链路 ServeContent → (*http.response).ReadFrom → (*net.TCPConn).ReadFrom 本身会用
// sendfile(2) 零拷贝发送，限速在 ResponseWriter 层分块插入等待，不包装文件 Reader。
func serveAccel(appCtx *AppContext, w http.ResponseWriter, r *http.Request, rw *responseInterceptor) {
	logger := appCtx.Logger

	filePath, err := secureJoinPath(appCtx.Config.AccelRoot, rw.accelPath)
	if err != nil {
		logger.Warn("X-Accel-Redirect 安全路径检查失败", "accel_path", rw.accelPath, "accel_root", appCtx.Config.AccelRoot, "error", err)
		accelError(w, http.StatusForbidden)
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			logger.Warn("X-Accel-Redirect 文件未找到", "path", filePath)
			accelError(w, http.StatusNotFound)
		} else {
			logger.Error("打开 X-Accel-Redirect 文件出错", "path", filePath, "error", err)
			accelError(w, http.StatusForbidden)
		}
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		logger.Error("读取 X-Accel-Redirect 文件信息出错", "path", filePath, "error", err)
		accelError(w, http.StatusInternalServerError)
		return
	}
	if fi.IsDir() {
		logger.Warn("X-Accel-Redirect 指向目录", "path", filePath)
		accelError(w, http.StatusForbidden)
		return
	}

	// PHP 设置的其他头（Content-Disposition 等）照常带上
	h := w.Header()
	h.Del("Content-Length")
	if strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		h.Del("Content-Type") // PHP 默认值，交给 ServeContent 按扩展名推断
	}
	if h.Get("ETag") == "" {
		h.Set("ETag", fmt.Sprintf(`"%x-%x"`, fi.ModTime().UnixNano(), fi.Size()))
	}

	tw := &throttledWriter{
		ResponseWriter: w,
		ctx:            r.Context(),
		chunk:          accelChunkSize,
	}
	// 指定了 token 时同一 token 的所有连接共享速率，否则只限制本连接
	if lim := appCtx.Limiters.Get(rw.accelTokenID, rw.accelLimitBytes); lim != nil {
		tw.lim = lim
		// 约 100ms 一块使速率平滑
		tw.chunk = max(1, min(accelChunkSize, rw.accelLimitBytes/10))
	}
	logger.Info("通过 X-Accel-Redirect 发送文件", "path", filePath, "range", r.Header.Get("Range"),
		"token_id", rw.accelTokenID, "limit_bytes", rw.accelLimitBytes)
	http.ServeContent(tw, r, fi.Name(), fi.ModTime(), f)
	logger.Debug("X-Accel-Redirect 发送结束", "path", filePath, "sent_bytes", tw.written)
}

// accelError 丢弃 PHP 设置的头（如 Content-Disposition）后返回错误状态
func accelError(w http.ResponseWriter, code int) {
	clear(w.Header())
	http.Error(w, http.StatusText(code), code)
}

// throttledWriter 在写入前按块等待限速器。
// 实现 ReadFrom 以保留 sendfile 零拷贝路径。
type throttledWriter struct {
	http.ResponseWriter
	ctx     context.Context
	lim     Limiter // nil 表示不限速
	chunk   int
	written int64
}

func (t *throttledWriter) Unwrap() http.ResponseWriter {
	return t.ResponseWriter
}

func (t *throttledWriter) wait(n int) error {
	if t.lim == nil {
		return nil
	}
	return t.lim.WaitN(t.ctx, n)
}

// ReadFrom 必须拆开 *io.LimitedReader：io.CopyN 会再套一层，而 TCPConn 只认
// 一层 LimitedReader{*os.File}，两层即退化为普通缓冲拷贝
func (t *throttledWriter) ReadFrom(src io.Reader) (int64, error) {
	remain := int64(-1) // -1 表示读到 EOF 为止
	if lr, ok := src.(*io.LimitedReader); ok {
		src, remain = lr.R, lr.N
		defer func() { lr.N = remain }()
	}

	var total int64
	for remain != 0 {
		n := int64(t.chunk)
		if remain > 0 {
			n = min(n, remain)
		}
		if err := t.wait(int(n)); err != nil {
			return total, err
		}
		m, err := io.CopyN(t.ResponseWriter, src, n)
		total += m
		t.written += m
		if remain > 0 {
			remain -= m
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Write 用于多段 Range（multipart）等不走 ReadFrom 的路径
func (t *throttledWriter) Write(p []byte) (int, error) {
	var total int
	for len(p) > 0 {
		n := min(len(p), t.chunk)
		if err := t.wait(n); err != nil {
			return total, err
		}
		m, err := t.ResponseWriter.Write(p[:n])
		total += m
		t.written += int64(m)
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}
