package main

import (
	"context"
	"errors"
	"fmt"
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

// secureJoinPath 安全地将基础路径和请求路径连接起来，并检查结果路径是否在基础路径内。
// 返回清理后的绝对路径或错误（如果路径无效或在基础路径之外）。
func secureJoinPath(basePath, requestedPath string) (string, error) {
	// 基础路径必须是绝对路径才能进行可靠的比较
	cleanBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("无法获取基础路径的绝对路径 '%s': %w", basePath, err)
	}

	targetPath := filepath.Join(cleanBasePath, requestedPath)
	targetPath = filepath.Clean(targetPath)

	// 获取目标路径的绝对路径（这也有助于清理 ".." 等）
	cleanTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return "", fmt.Errorf("无法获取目标路径的绝对路径 '%s': %w", targetPath, err)
	}

	// 安全检查：确保清理后的目标路径仍然在清理后的基础路径之下
	// 注意：使用 filepath.Separator 确保跨平台兼容性
	if !strings.HasPrefix(cleanTargetPath, cleanBasePath+string(filepath.Separator)) && cleanTargetPath != cleanBasePath {
		return "", fmt.Errorf("禁止访问路径 '%s' (解析为 '%s')，因为它在允许的基础目录 '%s' 之外", requestedPath, cleanTargetPath, cleanBasePath)
	}

	return cleanTargetPath, nil
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

	scriptPath, err := secureJoinPath(appCtx.Config.DocRoot, requestPath)
	if err != nil {
		appCtx.Logger.Warn("安全路径检查失败", "requested_path", requestPath, "doc_root", appCtx.Config.DocRoot, "error", err)
		return phpScript{}, http.StatusForbidden
	}
	fi, err := os.Stat(scriptPath)
	switch {
	case err == nil && !fi.IsDir():
		return phpScript{filename: scriptPath, name: requestPath}, 0
	case err == nil, os.IsNotExist(err), errors.Is(err, syscall.ENOTDIR):
		appCtx.Logger.Debug("请求的 .php 文件不存在", "requested_path", requestPath)
		return phpScript{}, http.StatusNotFound
	case os.IsPermission(err):
		appCtx.Logger.Warn("无权访问请求的 .php 文件", "path", scriptPath, "error", err)
		return phpScript{}, http.StatusForbidden
	default:
		appCtx.Logger.Error("检查请求的 .php 文件时出错", "path", scriptPath, "error", err)
		return phpScript{}, http.StatusInternalServerError
	}
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

// handleTryFiles 尝试直接提供静态文件。
// 返回 true 表示请求已处理完毕；返回 false 表示应继续交给 PHP 处理。
func handleTryFiles(appCtx *AppContext, w http.ResponseWriter, r *http.Request) bool {
	// 先规范化再判断后缀：否则 /index.php/、/index.php/. 不以 .php 结尾，
	// 清理后却指向 index.php，会被当作静态文件返回 PHP 源码
	requestPath := path.Clean("/" + r.URL.Path)
	if strings.HasSuffix(strings.ToLower(requestPath), ".php") {
		return false
	}

	filePath := filepath.Join(appCtx.Config.DocRoot, filepath.FromSlash(requestPath))

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		// ENOTDIR：如 /robots.txt/x，路径中间某段是文件
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			appCtx.Logger.Debug("tryFiles 未匹配到任何静态资源，转交 PHP 处理", "request_path", requestPath)
			return false
		}
		appCtx.Logger.Error("tryFiles 检查文件/目录时出错", "path", filePath, "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return true
	}

	if fileInfo.IsDir() {
		// 目录（包括 "/" 即 DocRoot 本身）交给 PHP 主入口处理
		appCtx.Logger.Debug("tryFiles 匹配到目录，转交 PHP 处理", "path", filePath)
		return false
	}

	appCtx.Logger.Debug("tryFiles 匹配到文件，直接提供", "path", filePath)
	http.ServeFile(w, r, filePath)
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
