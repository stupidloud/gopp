//go:build !frankenphp

package main

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/fcgi"
	"strings"
	"testing"
	"time"
)

// accelPHP 模拟下载脚本：?f= 文件路径，?t= token，?r= 速率（字节/秒）；无 ?f= 时输出 "php:<SCRIPT_FILENAME>"
func accelPHP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("f") == "" {
		fmt.Fprintf(w, "php:%s", fcgi.ProcessEnv(r)["SCRIPT_FILENAME"])
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="download"`)
	w.Header().Set("X-Accel-Redirect", q.Get("f"))
	if t := q.Get("t"); t != "" {
		w.Header().Set("X-Accel-Token-Id", t)
	}
	if rate := q.Get("r"); rate != "" {
		w.Header().Set("X-Accel-Limit-Rate", rate)
	}
	io.WriteString(w, "php body should be discarded")
}

func TestAccelServe(t *testing.T) {
	e := newTestEnv(t, accelPHP)
	content := fileContent(100000)
	e.writeFile(e.accelRoot, "files/data.bin", content)
	e.writeFile(e.accelRoot, "files/note.txt", "note")
	e.writeFile(e.docRoot, "index.php", "")

	t.Run("完整下载", func(t *testing.T) {
		resp, body := e.do("GET", "/?f=/files/data.bin", nil)
		if resp.StatusCode != 200 || body != content {
			t.Fatalf("状态 %d，响应体长度 %d", resp.StatusCode, len(body))
		}
		if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type = %q，不应沿用 PHP 默认的 text/html", ct)
		}
		if resp.Header.Get("Content-Disposition") == "" {
			t.Error("PHP 设置的 Content-Disposition 应保留")
		}
		for _, k := range []string{"X-Accel-Redirect", "X-Accel-Token-Id", "X-Accel-Limit-Rate"} {
			if resp.Header.Get(k) != "" {
				t.Errorf("%s 不应发给客户端", k)
			}
		}
		if etag := resp.Header.Get("ETag"); !strings.HasPrefix(etag, `"`) {
			t.Errorf("ETag = %q，应带引号", etag)
		}
	})

	t.Run("按扩展名推断 Content-Type", func(t *testing.T) {
		resp, body := e.do("GET", "/?f=/files/note.txt", nil)
		if body != "note" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
			t.Errorf("响应 %q，Content-Type %q", body, resp.Header.Get("Content-Type"))
		}
	})

	t.Run("HEAD 不发送文件体", func(t *testing.T) {
		resp, body := e.do("HEAD", "/?f=/files/data.bin", nil)
		if resp.StatusCode != 200 || body != "" || resp.ContentLength != int64(len(content)) {
			t.Errorf("状态 %d，响应体长度 %d，Content-Length %d", resp.StatusCode, len(body), resp.ContentLength)
		}
		// 同一连接上的后续请求不应被残留的文件体干扰
		resp, body = e.do("GET", "/?f=/files/note.txt", nil)
		if resp.StatusCode != 200 || body != "note" {
			t.Errorf("HEAD 之后的请求：状态 %d，响应 %q", resp.StatusCode, body)
		}
	})

	t.Run("Range", func(t *testing.T) {
		resp, body := e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=10-19"}})
		if resp.StatusCode != 206 || body != content[10:20] {
			t.Errorf("状态 %d，响应 %q", resp.StatusCode, body)
		}
		if cr := resp.Header.Get("Content-Range"); cr != "bytes 10-19/100000" {
			t.Errorf("Content-Range = %q", cr)
		}
	})

	t.Run("后缀 Range", func(t *testing.T) {
		resp, body := e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=-5"}})
		if resp.StatusCode != 206 || body != content[len(content)-5:] {
			t.Errorf("状态 %d，响应 %q", resp.StatusCode, body)
		}
	})

	t.Run("多段 Range", func(t *testing.T) {
		resp, body := e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=0-4,10-14"}})
		mediaType, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if resp.StatusCode != 206 || mediaType != "multipart/byteranges" {
			t.Fatalf("状态 %d，Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		mr := multipart.NewReader(strings.NewReader(body), params["boundary"])
		var parts []string
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			parts = append(parts, string(b))
		}
		if len(parts) != 2 || parts[0] != content[0:5] || parts[1] != content[10:15] {
			t.Errorf("各段内容 %q", parts)
		}
	})

	t.Run("非法 Range 不被纠正", func(t *testing.T) {
		resp, body := e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=5-2"}})
		if resp.StatusCode == 206 {
			t.Errorf("bytes=5-2 不应返回 206：%q", body[:min(len(body), 20)])
		}
	})

	t.Run("If-Range 与 If-None-Match", func(t *testing.T) {
		resp, _ := e.do("HEAD", "/?f=/files/data.bin", nil)
		etag := resp.Header.Get("ETag")

		resp, body := e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=0-9"}, "If-Range": {etag}})
		if resp.StatusCode != 206 || body != content[:10] {
			t.Errorf("If-Range 匹配：状态 %d", resp.StatusCode)
		}
		resp, body = e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=0-9"}, "If-Range": {`"stale"`}})
		if resp.StatusCode != 200 || body != content {
			t.Errorf("If-Range 不匹配应返回完整文件：状态 %d", resp.StatusCode)
		}
		resp, _ = e.do("GET", "/?f=/files/data.bin", http.Header{"If-None-Match": {etag}})
		if resp.StatusCode != 304 {
			t.Errorf("If-None-Match 匹配：状态 %d，期望 304", resp.StatusCode)
		}
	})

	t.Run("416", func(t *testing.T) {
		resp, _ := e.do("GET", "/?f=/files/data.bin", http.Header{"Range": {"bytes=200000-"}})
		if resp.StatusCode != 416 {
			t.Errorf("状态 %d，期望 416", resp.StatusCode)
		}
	})

	errorCases := []struct {
		name, target string
		want         int
	}{
		{"文件不存在", "/?f=/files/missing.bin", 404},
		{"目录", "/?f=/files", 403},
		{"越界的路径被限制在 accel_root 内", "/?f=/../../etc/passwd", 404},
	}
	for _, tt := range errorCases {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := e.do("GET", tt.target, nil)
			if resp.StatusCode != tt.want {
				t.Errorf("状态 %d，期望 %d", resp.StatusCode, tt.want)
			}
			if resp.Header.Get("Content-Disposition") != "" {
				t.Error("错误响应不应带 PHP 的 Content-Disposition")
			}
		})
	}
}

// 速率低于块大小（256KB/s）时不应中断，且耗时符合限速
func TestAccelLowRate(t *testing.T) {
	e := newTestEnv(t, accelPHP)
	content := fileContent(250 << 10)
	e.writeFile(e.accelRoot, "big.bin", content)

	start := time.Now()
	resp, body := e.do("GET", "/?f=/big.bin&t=user&r=102400", nil)
	elapsed := time.Since(start)
	if resp.StatusCode != 200 || !bytes.Equal([]byte(body), []byte(content)) {
		t.Fatalf("状态 %d，响应体长度 %d", resp.StatusCode, len(body))
	}
	// 桶初始为 1 秒的量：(250K-100K)/100K = 1.5s
	if elapsed < 1300*time.Millisecond || elapsed > 2200*time.Millisecond {
		t.Errorf("耗时 %v，期望约 1.5s", elapsed)
	}
}
