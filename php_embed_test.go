//go:build frankenphp

package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newEmbedEnv 启动内嵌 PHP 的 gopp；files 为 doc_root 下的脚本（需在 Init 前写好，worker 脚本必须存在）
func newEmbedEnv(t *testing.T, workerFile string, files map[string]string) (*AppContext, *httptest.Server) {
	t.Helper()
	cfg := defaultConfig
	cfg.DocRoot = t.TempDir()
	cfg.AccelRoot = t.TempDir()
	cfg.TrustedProxies = []string{"127.0.0.1"}
	cfg.PHPThreads = 4
	cfg.PHPWorkerFile = workerFile
	cfg.PHPWorkerNum = 1
	if err := cfg.prepare(); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		root := cfg.DocRoot
		if strings.HasPrefix(name, "accel:") {
			root, name = cfg.AccelRoot, strings.TrimPrefix(name, "accel:")
		}
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	appCtx := &AppContext{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var err error
	if appCtx.PHP, err = newPHPBackend(appCtx); err != nil {
		t.Fatal(err)
	}
	appCtx.Limiters = NewLimiterManager(cfg, appCtx.Logger)
	srv := httptest.NewServer(createPHPHandler(appCtx))
	t.Cleanup(func() {
		srv.Close()
		appCtx.PHP.Close()
	})
	return appCtx, srv
}

func embedDo(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

const dumpServerPHP = `<?php
header('Content-Type: application/json');
$keys = ['SCRIPT_FILENAME', 'SCRIPT_NAME', 'REQUEST_URI', 'DOCUMENT_ROOT', 'REMOTE_ADDR',
	'HTTP_COOKIE', 'HTTP_CLIENT_IP', 'HTTP_PROXY', 'HTTP_X_CUSTOM'];
$out = [];
foreach ($keys as $k) { $out[$k] = $_SERVER[$k] ?? null; }
$out['cookie'] = $_COOKIE;
$out['post'] = $_POST;
echo json_encode($out);
`

func TestEmbedPHP(t *testing.T) {
	appCtx, srv := newEmbedEnv(t, "", map[string]string{
		"index.php":    dumpServerPHP,
		"sub/page.php": dumpServerPHP,
	})
	docRoot := appCtx.Config.DocRoot

	get := func(target string, form url.Values, header http.Header) map[string]any {
		t.Helper()
		method, reqBody := "GET", io.Reader(nil)
		if form != nil {
			method, reqBody = "POST", strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, srv.URL+target, reqBody)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for k, v := range header {
			req.Header[k] = v
		}
		resp, body := embedDo(t, req)
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s：状态 %d，%s", method, target, resp.StatusCode, body)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("%s：%v", body, err)
		}
		return m
	}

	t.Run("非 .php 请求交给主入口，REQUEST_URI 保持原样", func(t *testing.T) {
		m := get("/some/route?x=1", nil, nil)
		want := map[string]any{
			"SCRIPT_FILENAME": filepath.Join(docRoot, "index.php"),
			"SCRIPT_NAME":     "/index.php",
			"REQUEST_URI":     "/some/route?x=1",
			"DOCUMENT_ROOT":   docRoot,
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s = %v，期望 %v", k, m[k], v)
			}
		}
	})

	t.Run("直接请求 .php", func(t *testing.T) {
		m := get("/sub/page.php?y=2", nil, nil)
		if m["SCRIPT_FILENAME"] != filepath.Join(docRoot, "sub/page.php") || m["REQUEST_URI"] != "/sub/page.php?y=2" {
			t.Errorf("%v", m)
		}
	})

	t.Run("请求头与真实 IP", func(t *testing.T) {
		m := get("/", nil, http.Header{
			"X-Forwarded-For": {"1.2.3.4"},
			"Client_ip":       {"6.6.6.6"},
			"Proxy":           {"http://evil:8080"},
			"Cookie":          {"a=1", "b=2"},
			"X-Custom":        {"ok"},
		})
		if m["REMOTE_ADDR"] != "1.2.3.4" {
			t.Errorf("REMOTE_ADDR = %v", m["REMOTE_ADDR"])
		}
		if m["HTTP_CLIENT_IP"] != nil || m["HTTP_PROXY"] != nil {
			t.Errorf("下划线头 / Proxy 头不应传给 PHP：%v %v", m["HTTP_CLIENT_IP"], m["HTTP_PROXY"])
		}
		if m["HTTP_X_CUSTOM"] != "ok" {
			t.Errorf("HTTP_X_CUSTOM = %v", m["HTTP_X_CUSTOM"])
		}
		if c, _ := m["cookie"].(map[string]any); c["a"] != "1" || c["b"] != "2" {
			t.Errorf("$_COOKIE = %v", m["cookie"])
		}
	})

	t.Run("POST 表单", func(t *testing.T) {
		m := get("/", url.Values{"k": {"v"}}, nil)
		if p, _ := m["post"].(map[string]any); p["k"] != "v" {
			t.Errorf("$_POST = %v", m["post"])
		}
	})
}

func TestEmbedAccel(t *testing.T) {
	content := fileContent(300000)
	_, srv := newEmbedEnv(t, "", map[string]string{
		"index.php": `<?php
header('Content-Disposition: attachment; filename="d.bin"');
header('X-Accel-Redirect: ' . $_GET['f']);
if (isset($_GET['r'])) { header('X-Accel-Limit-Rate: ' . $_GET['r']); }
echo "php body should be discarded";`,
		"accel:files/data.bin": content,
	})

	req, _ := http.NewRequest("GET", srv.URL+"/?f=/files/data.bin", nil)
	resp, body := embedDo(t, req)
	if resp.StatusCode != 200 || body != content || resp.Header.Get("X-Accel-Redirect") != "" {
		t.Fatalf("状态 %d，长度 %d", resp.StatusCode, len(body))
	}
	if resp.Header.Get("Content-Disposition") == "" || resp.ContentLength != int64(len(content)) {
		t.Errorf("Content-Disposition %q，Content-Length %d", resp.Header.Get("Content-Disposition"), resp.ContentLength)
	}

	req, _ = http.NewRequest("GET", srv.URL+"/?f=/files/data.bin", nil)
	req.Header.Set("Range", "bytes=10-19")
	resp, body = embedDo(t, req)
	if resp.StatusCode != 206 || body != content[10:20] {
		t.Errorf("Range：状态 %d，%q", resp.StatusCode, body)
	}

	req, _ = http.NewRequest("GET", srv.URL+"/?f=/files/missing.bin", nil)
	if resp, _ := embedDo(t, req); resp.StatusCode != 404 {
		t.Errorf("不存在的文件：状态 %d", resp.StatusCode)
	}
}

// worker 模式：主入口的请求由常驻的 worker 处理，请求间保留状态
func TestEmbedWorker(t *testing.T) {
	_, srv := newEmbedEnv(t, "worker.php", map[string]string{
		"index.php": `<?php echo "not worker";`,
		"worker.php": `<?php
$n = 0;
while (frankenphp_handle_request(function () use (&$n) {
	$n++;
	echo "worker:$n:" . $_SERVER['REQUEST_URI'];
})) {}`,
		"other.php": `<?php echo "other";`,
	})

	for i, want := range []string{"worker:1:/a", "worker:2:/b"} {
		req, _ := http.NewRequest("GET", srv.URL+[]string{"/a", "/b"}[i], nil)
		if _, body := embedDo(t, req); body != want {
			t.Errorf("第 %d 次请求 = %q，期望 %q", i+1, body, want)
		}
	}
	req, _ := http.NewRequest("GET", srv.URL+"/other.php", nil)
	if _, body := embedDo(t, req); body != "other" {
		t.Errorf("其他 .php 脚本应照常执行：%q", body)
	}
}
