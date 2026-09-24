//go:build frankenphp

package main

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/dunglas/frankenphp"
)

// embedWorkerName 是 php_worker_file 对应的 FrankenPHP worker 名称
const embedWorkerName = "gopp"

// embedBackend 通过 FrankenPHP 在进程内执行 PHP（-tags frankenphp 构建，需要 ZTS + embed 的 libphp）
type embedBackend struct {
	appCtx       *AppContext
	workerScript string // 交给 worker 处理的脚本（即 main_php_file 的 SCRIPT_FILENAME），为空表示未启用 worker
}

func newPHPBackend(appCtx *AppContext) (phpBackend, error) {
	cfg := appCtx.Config
	opts := []frankenphp.Option{
		frankenphp.WithLogger(appCtx.Logger),
		frankenphp.WithNumThreads(cfg.PHPThreads),
		frankenphp.WithPhpIni(cfg.PHPIni),
	}
	b := &embedBackend{appCtx: appCtx}
	if cfg.PHPWorkerFile != "" {
		opts = append(opts, frankenphp.WithWorkers(embedWorkerName, filepath.Join(cfg.DocRoot, cfg.PHPWorkerFile), cfg.PHPWorkerNum))
		b.workerScript = filepath.Join(cfg.DocRoot, cfg.MainPHPFile)
	}
	if err := frankenphp.Init(opts...); err != nil {
		return nil, err
	}
	appCtx.Logger.Info("内嵌 PHP", "version", frankenphp.Version().Version, "worker_file", cfg.PHPWorkerFile)
	return b, nil
}

func (b *embedBackend) ServePHP(w http.ResponseWriter, r *http.Request, script phpScript) {
	cfg := b.appCtx.Config
	logger := b.appCtx.Logger

	// FrankenPHP 按 URL 路径确定 SCRIPT_NAME / SCRIPT_FILENAME，因此把路径改写为已解析的脚本；
	// REQUEST_URI 通过 WithOriginalRequest 仍取原始请求
	pr := r.Clone(r.Context())
	pr.URL.Path, pr.URL.RawPath = script.name, ""
	// REMOTE_ADDR 取自 RemoteAddr
	_, port, _ := net.SplitHostPort(r.RemoteAddr)
	pr.RemoteAddr = net.JoinHostPort(GetRealIP(r, cfg.trustedProxyNets), port)
	// FrankenPHP 不过滤请求头，且多个 Cookie 头以 ", " 连接（PHP 无法正确解析）
	for k := range pr.Header {
		if dropHeader(k) {
			delete(pr.Header, k)
		}
	}
	if c := pr.Header["Cookie"]; len(c) > 1 {
		pr.Header["Cookie"] = []string{strings.Join(c, "; ")}
	}

	opts := []frankenphp.RequestOption{
		frankenphp.WithRequestResolvedDocumentRoot(cfg.DocRoot),
		frankenphp.WithOriginalRequest(r),
		frankenphp.WithRequestLogger(logger),
	}
	if b.workerScript != "" && script.filename == b.workerScript {
		opts = append(opts, frankenphp.WithWorkerName(embedWorkerName))
	}
	fr, err := frankenphp.NewRequestWithContext(pr, opts...)
	if err == nil {
		err = frankenphp.ServeHTTP(w, fr)
	}
	if err != nil {
		var rejected frankenphp.ErrRejected
		if errors.As(err, &rejected) {
			return // FrankenPHP 已写入错误响应
		}
		logger.Error("执行 PHP 出错", "script", script.filename, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (b *embedBackend) Close() {
	frankenphp.Shutdown()
}
