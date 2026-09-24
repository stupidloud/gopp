package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yookoala/gofast"
)

// testEnv 是一套完整的测试环境：临时 doc_root / accel_root、模拟的 PHP-FPM 后端和 gopp 服务器
type testEnv struct {
	t         *testing.T
	docRoot   string
	accelRoot string
	appCtx    *AppContext
	srv       *httptest.Server
}

// fakePHP 模拟 PHP-FPM：默认输出 "php:<SCRIPT_FILENAME>"；
// 测试可通过 handler 自定义响应（例如设置 X-Accel-Redirect）
func newTestEnv(t *testing.T, handler http.HandlerFunc) *testEnv {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "php:%s", fcgi.ProcessEnv(r)["SCRIPT_FILENAME"])
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go fcgi.Serve(ln, handler)
	t.Cleanup(func() { ln.Close() })

	cfg := defaultConfig
	cfg.DocRoot = t.TempDir()
	cfg.AccelRoot = t.TempDir()
	cfg.FPMNetwork = "tcp"
	cfg.FPMAddress = ln.Addr().String()
	if err := cfg.prepare(); err != nil {
		t.Fatal(err)
	}

	appCtx := &AppContext{
		Config:      cfg,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		ConnFactory: gofast.SimpleConnFactory(cfg.FPMNetwork, cfg.FPMAddress),
	}
	appCtx.Limiters = NewLimiterManager(cfg, appCtx.Logger)
	srv := httptest.NewServer(createPHPHandler(appCtx))
	t.Cleanup(srv.Close)

	return &testEnv{t: t, docRoot: cfg.DocRoot, accelRoot: cfg.AccelRoot, appCtx: appCtx, srv: srv}
}

// writeFile 在 root 下创建文件（自动创建父目录）
func (e *testEnv) writeFile(root, name, content string) {
	e.t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// do 发送请求，返回响应和完整响应体
func (e *testEnv) do(method, target string, header http.Header) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+target, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, vv := range header {
		req.Header[k] = vv
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("%s %s: 读取响应体: %v", method, target, err)
	}
	return resp, string(body)
}

func TestTryFiles(t *testing.T) {
	e := newTestEnv(t, nil)
	e.writeFile(e.docRoot, "index.php", "<?php SECRET_SOURCE")
	e.writeFile(e.docRoot, "static.txt", "hello static")
	e.writeFile(e.docRoot, "sub/a.txt", "sub file")
	e.writeFile(e.docRoot, "sub/page.php", "")
	e.writeFile(e.docRoot, "dir.php/x", "")
	e.writeFile(e.docRoot, ".env", "DB_PASSWORD=secret")
	e.writeFile(e.docRoot, ".git/config", "[core]")
	e.writeFile(e.docRoot, "sub/.htaccess", "deny")
	e.writeFile(e.docRoot, ".hidden.php", "")
	e.writeFile(e.docRoot, ".well-known/acme-challenge/tok", "acme")
	mainScript := "php:" + filepath.Join(e.docRoot, "index.php")

	tests := []struct {
		name, method, target string
		wantStatus           int
		wantBody             string
	}{
		{"静态文件", "GET", "/static.txt", 200, "hello static"},
		{"静态文件 HEAD", "HEAD", "/static.txt", 200, ""},
		{"子目录静态文件", "GET", "/sub/a.txt", 200, "sub file"},
		{"根目录交给 PHP", "GET", "/", 200, mainScript},
		{"子目录交给 PHP", "GET", "/sub/", 200, mainScript},
		{"不存在的路径交给 PHP", "GET", "/no/such/route", 200, mainScript},
		{"路径中间是文件交给 PHP", "GET", "/static.txt/x", 200, mainScript},
		{"PHP 脚本", "GET", "/index.php", 200, mainScript},
		{"子目录 PHP 脚本", "GET", "/sub/page.php", 200, "php:" + filepath.Join(e.docRoot, "sub/page.php")},
		{"PHP 脚本不存在返回 404", "GET", "/missing.php", 404, "Not Found\n"},
		{"以 .php 结尾的目录返回 404", "GET", "/dir.php", 404, "Not Found\n"},
		{"隐藏文件", "GET", "/.env", 403, "Forbidden\n"},
		{"隐藏目录", "GET", "/.git/config", 403, "Forbidden\n"},
		{"子目录中的隐藏文件", "GET", "/sub/.htaccess", 403, "Forbidden\n"},
		{"不存在的隐藏路径", "GET", "/.svn/entries", 403, "Forbidden\n"},
		{"隐藏的 PHP 脚本", "GET", "/.hidden.php", 403, "Forbidden\n"},
		{"经 .. 规范化后的隐藏文件", "GET", "/sub/../.env", 403, "Forbidden\n"},
		{".well-known 放行", "GET", "/.well-known/acme-challenge/tok", 200, "acme"},
		{"越界的 PHP 路径被限制在 doc_root 内", "GET", "/../../etc/x.php", 404, "Not Found\n"},
		// 以下路径清理后指向 index.php，不得作为静态文件返回源码
		{"末尾斜杠不泄露源码", "GET", "/index.php/", 200, mainScript},
		{"末尾点不泄露源码", "GET", "/index.php/.", 200, mainScript},
		{"大写后缀不泄露源码", "GET", "/INDEX.PHP", 200, mainScript},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do(tt.method, tt.target, nil)
			if resp.StatusCode != tt.wantStatus || body != tt.wantBody {
				t.Errorf("%s %s = %d %q，期望 %d %q", tt.method, tt.target, resp.StatusCode, body, tt.wantStatus, tt.wantBody)
			}
		})
	}
}

// 软链接：指向根目录内的相对软链接可用；指向根目录外或使用绝对路径的软链接一律拒绝
func TestSymlinkEscape(t *testing.T) {
	e := newTestEnv(t, accelPHP)
	outside := t.TempDir()
	e.writeFile(outside, "secret.txt", "SECRET")
	e.writeFile(outside, "secret.php", "")
	e.writeFile(e.docRoot, "real/a.txt", "inside")
	e.writeFile(e.docRoot, "real/b.php", "")
	e.writeFile(e.docRoot, "index.php", "")
	e.writeFile(e.accelRoot, "real/f.bin", "file")

	symlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	symlink("real", filepath.Join(e.docRoot, "rel"))                               // 根内、相对
	symlink(filepath.Join(e.docRoot, "real"), filepath.Join(e.docRoot, "abs"))     // 根内、绝对
	symlink(outside, filepath.Join(e.docRoot, "out"))                              // 根外
	symlink("real", filepath.Join(e.accelRoot, "rel"))                             // 根内、相对
	symlink(outside, filepath.Join(e.accelRoot, "out"))                            // 根外
	symlink(filepath.Join(e.accelRoot, "real"), filepath.Join(e.accelRoot, "abs")) // 根内、绝对

	tests := []struct {
		name, target string
		wantStatus   int
		wantBody     string
	}{
		{"静态：根内相对软链接", "/rel/a.txt", 200, "inside"},
		{"静态：根内绝对软链接", "/abs/a.txt", 403, "Forbidden\n"},
		{"静态：根外软链接", "/out/secret.txt", 403, "Forbidden\n"},
		{"PHP：根内相对软链接", "/rel/b.php", 200, "php:" + filepath.Join(e.docRoot, "rel/b.php")},
		{"PHP：根外软链接", "/out/secret.php", 403, "Forbidden\n"},
		{"X-Accel：根内相对软链接", "/?f=/rel/f.bin", 200, "file"},
		{"X-Accel：根内绝对软链接", "/?f=/abs/f.bin", 403, "Forbidden\n"},
		{"X-Accel：根外软链接", "/?f=/out/secret.txt", 403, "Forbidden\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := e.do("GET", tt.target, nil)
			if resp.StatusCode != tt.wantStatus || body != tt.wantBody {
				t.Errorf("GET %s = %d %q，期望 %d %q", tt.target, resp.StatusCode, body, tt.wantStatus, tt.wantBody)
			}
		})
	}
}
