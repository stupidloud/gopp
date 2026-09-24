package main

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/yookoala/gofast"
)

// GetRealIP 获取客户端真实 IP。
// 只有直连地址（RemoteAddr）属于可信代理时才采信 X-Forwarded-For / X-Real-IP：
// X-Forwarded-For 从右往左跳过可信代理，取第一个不可信地址；遇到非法值即停止，
// 以已确认的最后一跳为准。
func GetRealIP(r *http.Request, trustedProxies []netip.Prefix) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	ip := ap.Addr().Unmap()
	if !isTrustedProxy(ip, trustedProxies) {
		return ip.String()
	}

	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		hops := strings.Split(strings.Join(values, ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break
			}
			ip = hop.Unmap()
			if !isTrustedProxy(ip, trustedProxies) {
				break
			}
		}
		return ip.String()
	}

	if realIP, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return realIP.Unmap().String()
	}
	return ip.String()
}

func isTrustedProxy(ip netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, p := range trustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// openInRoot 打开 root 下的 urlPath（以 "/" 分隔），不允许逃逸出 root：
// 跟随软链接，但指向 root 之外或使用绝对路径的软链接会报错（os.Root 语义，基于 openat，无 TOCTOU）
func openInRoot(root, urlPath string) (*os.File, error) {
	rel := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	if rel == "" {
		rel = "."
	}
	return os.OpenInRoot(root, filepath.FromSlash(rel))
}

// isNotFound 判断是否为"不存在"类错误；ENOTDIR 如 /robots.txt/x，路径中间某段是文件
func isNotFound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// phpScript 是本次请求要执行的 PHP 脚本
type phpScript struct {
	filename string // SCRIPT_FILENAME
	name     string // SCRIPT_NAME
}

type phpScriptKey struct{}

// resolvePHPScript 确定要执行的 PHP 脚本：请求路径以 .php 结尾时执行该脚本，否则执行主入口。
// 在进入 gofast 之前完成，出错时返回对应的 HTTP 状态码（gofast 会把 SessionHandler 的错误一律变成 500）。
func resolvePHPScript(appCtx *AppContext, requestPath string) (phpScript, int) {
	requestPath = path.Clean("/" + requestPath)
	if !strings.HasSuffix(requestPath, ".php") {
		return phpScript{
			filename: filepath.Join(appCtx.Config.DocRoot, appCtx.Config.MainPHPFile),
			name:     "/" + appCtx.Config.MainPHPFile,
		}, 0
	}

	f, err := openInRoot(appCtx.Config.DocRoot, requestPath)
	if err != nil {
		if isNotFound(err) {
			appCtx.Logger.Debug("请求的 .php 文件不存在", "requested_path", requestPath)
			return phpScript{}, http.StatusNotFound
		}
		appCtx.Logger.Warn("拒绝访问请求的 .php 文件", "requested_path", requestPath, "error", err)
		return phpScript{}, http.StatusForbidden
	}
	fi, err := f.Stat()
	f.Close()
	if err != nil {
		appCtx.Logger.Error("检查请求的 .php 文件时出错", "requested_path", requestPath, "error", err)
		return phpScript{}, http.StatusInternalServerError
	}
	if fi.IsDir() {
		return phpScript{}, http.StatusNotFound
	}
	return phpScript{
		filename: filepath.Join(appCtx.Config.DocRoot, filepath.FromSlash(requestPath)),
		name:     requestPath,
	}, 0
}

// phpScriptRouterSessionHandler 按 resolvePHPScript 的结果设置 SCRIPT_FILENAME 和 SCRIPT_NAME
func phpScriptRouterSessionHandler(appCtx *AppContext) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			script := req.Raw.Context().Value(phpScriptKey{}).(phpScript)
			req.Params["SCRIPT_FILENAME"] = script.filename
			req.Params["SCRIPT_NAME"] = script.name
			appCtx.Logger.Debug("PHP 脚本路由", "script_filename", script.filename, "script_name", script.name)

			return inner(client, req)
		}
	}
}

// basicFastCGISetupSessionHandler 设置基本的 FastCGI 参数，如 DOCUMENT_ROOT 和 REMOTE_ADDR。
func basicFastCGISetupSessionHandler(appCtx *AppContext) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			req.Params["DOCUMENT_ROOT"] = appCtx.Config.DocRoot

			realIP := GetRealIP(req.Raw, appCtx.Config.trustedProxyNets)
			req.Params["REMOTE_ADDR"] = realIP
			if forwardedFor := req.Raw.Header.Get("X-Forwarded-For"); forwardedFor != "" {
				req.Params["HTTP_X_FORWARDED_FOR"] = forwardedFor
			}
			if realIPHeader := req.Raw.Header.Get("X-Real-IP"); realIPHeader != "" {
				req.Params["HTTP_X_REAL_IP"] = realIPHeader
			}
			appCtx.Logger.Debug("设置基本 FastCGI 参数", "doc_root", appCtx.Config.DocRoot, "remote_addr", realIP)

			return inner(client, req)
		}
	}
}

// createPHPHandler 创建处理PHP请求的HTTP处理器
func createPHPHandler(appCtx *AppContext) http.Handler {
	clientFactory := gofast.SimpleClientFactory(appCtx.ConnFactory)

	phpSessionHandler := gofast.Chain(
		gofast.BasicParamsMap,                   // 基本 CGI 参数
		gofast.MapHeader,                        // HTTP 请求头
		basicFastCGISetupSessionHandler(appCtx), // 设置 DOCUMENT_ROOT, REMOTE_ADDR 等
		phpScriptRouterSessionHandler(appCtx),   // 设置 SCRIPT_FILENAME, SCRIPT_NAME
	)(gofast.BasicSession) // 处理 FastCGI 通信

	phpFSHandler := gofast.NewHandler(
		phpSessionHandler,
		clientFactory,
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHiddenPath(r.URL.Path) {
			appCtx.Logger.Debug("拒绝访问隐藏文件", "request_path", r.URL.Path)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if handleTryFiles(appCtx, w, r) {
			return
		}

		script, status := resolvePHPScript(appCtx, r.URL.Path)
		if status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), phpScriptKey{}, script))

		rw := &responseInterceptor{
			ResponseWriter: w,
			headersSent:    false,
			accelPath:      "",
			appCtx:         appCtx,
		}

		phpFSHandler.ServeHTTP(rw, r)

		if rw.accelPath != "" {
			serveAccel(appCtx, w, r, rw)
		}
	})
}

// isHiddenPath 判断路径中是否有以 "." 开头的段（.env、.git/ 等），.well-known 除外
func isHiddenPath(urlPath string) bool {
	for _, seg := range strings.Split(path.Clean("/"+urlPath), "/") {
		if strings.HasPrefix(seg, ".") && seg != ".well-known" {
			return true
		}
	}
	return false
}

// handleTryFiles 尝试直接提供静态文件。
// 返回 true 表示请求已处理完毕；返回 false 表示应继续交给 PHP 处理。
func handleTryFiles(appCtx *AppContext, w http.ResponseWriter, r *http.Request) bool {
	// 先规范化再判断后缀：否则 /index.php/、/index.php/. 不以 .php 结尾，
	// 清理后却指向 index.php，会被当作静态文件返回 PHP 源码
	requestPath := path.Clean("/" + r.URL.Path)
	if strings.HasSuffix(strings.ToLower(requestPath), ".php") {
		return false
	}

	f, err := openInRoot(appCtx.Config.DocRoot, requestPath)
	if err != nil {
		if isNotFound(err) {
			appCtx.Logger.Debug("tryFiles 未匹配到任何静态资源，转交 PHP 处理", "request_path", requestPath)
			return false
		}
		appCtx.Logger.Warn("tryFiles 拒绝访问", "request_path", requestPath, "error", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return true
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		appCtx.Logger.Error("tryFiles 读取文件信息出错", "request_path", requestPath, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return true
	}
	if fileInfo.IsDir() {
		// 目录（包括 "/" 即 DocRoot 本身）交给 PHP 主入口处理
		appCtx.Logger.Debug("tryFiles 匹配到目录，转交 PHP 处理", "request_path", requestPath)
		return false
	}

	appCtx.Logger.Debug("tryFiles 匹配到文件，直接提供", "request_path", requestPath)
	http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), f)
	return true
}

// responseInterceptor 是一个拦截响应的自定义ResponseWriter
type responseInterceptor struct {
	http.ResponseWriter
	headersSent     bool
	accelPath       string
	accelTokenID    string
	accelLimitBytes int // 速率限制 (字节/s)，0 表示未指定
	appCtx          *AppContext
}

// WriteHeader 拦截WriteHeader调用以检测X-Accel-Redirect和X-Accel-Token-Id
func (rw *responseInterceptor) WriteHeader(code int) {
	if rw.headersSent {
		return
	}

	accelPath := rw.Header().Get("X-Accel-Redirect")
	if accelPath != "" {
		rw.accelPath = accelPath
		rw.Header().Del("X-Accel-Redirect")

		// 检查 X-Accel-Token-Id
		tokenID := rw.Header().Get("X-Accel-Token-Id")
		if tokenID != "" {
			rw.accelTokenID = tokenID
			rw.Header().Del("X-Accel-Token-Id")
		}
		// 检查 X-Accel-Limit-Rate (字节/秒)
		limitStr := rw.Header().Get("X-Accel-Limit-Rate")
		if limitStr != "" {
			limit, err := strconv.Atoi(limitStr)
			if err == nil && limit > 0 {
				rw.accelLimitBytes = limit
				rw.appCtx.Logger.Debug("收到 X-Accel-Limit-Rate", "limit_bytes", limit, "token_id", tokenID)
			} else {
				rw.appCtx.Logger.Warn("收到无效的 X-Accel-Limit-Rate 值，忽略速率限制", "value", limitStr, "token_id", tokenID)
			}
			rw.Header().Del("X-Accel-Limit-Rate")
		}

		// X-Accel-Redirect: 延迟写入头
		return
	}

	rw.ResponseWriter.WriteHeader(code)
	rw.headersSent = true
}

func (rw *responseInterceptor) Write(b []byte) (int, error) {
	if rw.accelPath != "" {
		return len(b), nil
	}
	if !rw.headersSent {
		// 确保在写入响应体前发送头信息
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *responseInterceptor) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok && rw.headersSent {
		flusher.Flush()
	}
}
