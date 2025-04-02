package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/yookoala/gofast"
)

// GetRealIP 从请求中获取真实的客户端IP地址
// 如果请求来自可信代理，会检查X-Forwarded-For头
func GetRealIP(r *http.Request, trustedProxies []string) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // 如果无法解析RemoteAddr，则直接返回原始值
	}

	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		for i := 0; i < len(ips); i++ {
			clientIP := strings.TrimSpace(ips[i])
			if clientIP == "" {
				continue
			}

			// 检查 clientIP 是否为可信代理
			isTrustedProxy := false
			for _, proxy := range trustedProxies {
				if proxy == clientIP {
					isTrustedProxy = true
					break
				}
				// 支持CIDR格式
				if strings.Contains(proxy, "/") {
					_, ipnet, cidrErr := net.ParseCIDR(proxy)
					if cidrErr == nil && ipnet.Contains(net.ParseIP(clientIP)) {
						isTrustedProxy = true
						break
					}
				}
			}

			if !isTrustedProxy {
				return clientIP
			}
		}
	}

	if clientIP := r.Header.Get("X-Real-IP"); clientIP != "" {
		return clientIP
	}

	return ip
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

// phpScriptRouterSessionHandler 是一个 gofast.SessionHandler 中间件，
// 用于根据请求路径动态设置 SCRIPT_FILENAME 和 SCRIPT_NAME。
func phpScriptRouterSessionHandler(appCtx *AppContext) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			requestPath := req.Raw.URL.Path
			scriptToExecute := appCtx.Config.MainPHPFile
			scriptName := "/" + appCtx.Config.MainPHPFile

			if strings.HasSuffix(requestPath, ".php") {
				cleanTargetPath, err := secureJoinPath(appCtx.Config.DocRoot, requestPath)
				if err != nil {
					appCtx.Logger.Warn("安全路径检查失败", "requested_path", requestPath, "doc_root", appCtx.Config.DocRoot, "error", err)
					return nil, fmt.Errorf("forbidden: invalid or disallowed path %s", requestPath)
				}
				requestedScriptPath := cleanTargetPath

				if _, err := os.Stat(requestedScriptPath); err == nil {
					scriptToExecute = requestPath
					scriptName = requestPath
				} else if os.IsNotExist(err) {
					appCtx.Logger.Debug("请求的 .php 文件不存在", "requested_path", requestPath)
					return nil, fmt.Errorf("not found: script %s not found", requestPath)
				} else {
					appCtx.Logger.Error("检查请求的 .php 文件时出错", "path", requestedScriptPath, "error", err)
					return nil, fmt.Errorf("internal server error checking script %s", requestPath)
				}
			}

			req.Params["SCRIPT_FILENAME"] = filepath.Join(appCtx.Config.DocRoot, scriptToExecute)
			req.Params["SCRIPT_NAME"] = scriptName
			appCtx.Logger.Debug("PHP 脚本路由", "script_filename", req.Params["SCRIPT_FILENAME"], "script_name", req.Params["SCRIPT_NAME"])

			return inner(client, req)
		}
	}
}

// basicFastCGISetupSessionHandler 设置基本的 FastCGI 参数，如 DOCUMENT_ROOT 和 REMOTE_ADDR。
func basicFastCGISetupSessionHandler(appCtx *AppContext) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			req.Params["DOCUMENT_ROOT"] = appCtx.Config.DocRoot

			realIP := GetRealIP(req.Raw, appCtx.Config.TrustedProxies)
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
		gofast.MapRemoteHost,                    // REMOTE_HOST
		basicFastCGISetupSessionHandler(appCtx), // 设置 DOCUMENT_ROOT, REMOTE_ADDR 等
		phpScriptRouterSessionHandler(appCtx),   // 设置 SCRIPT_FILENAME, SCRIPT_NAME
	)(gofast.BasicSession) // 处理 FastCGI 通信

	phpFSHandler := gofast.NewHandler(
		phpSessionHandler,
		clientFactory,
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleTryFiles(appCtx, w, r)

		rw := &responseInterceptor{
			ResponseWriter: w,
			headersSent:    false,
			accelPath:      "",
			appCtx:         appCtx,
		}

		phpFSHandler.ServeHTTP(rw, r)

		if rw.accelPath != "" {
			rw.appCtx.Logger.Info("处理 X-Accel-Redirect", "accel_path", rw.accelPath, "request_uri", r.URL.Path)

			cleanTargetPath, err := secureJoinPath(appCtx.Config.AccelRoot, rw.accelPath)
			if err != nil {
				rw.appCtx.Logger.Warn("X-Accel-Redirect 安全路径检查失败", "accel_path", rw.accelPath, "accel_root", appCtx.Config.AccelRoot, "error", err)
				return
			}
			fileInfo, err := os.Stat(cleanTargetPath)
			if os.IsNotExist(err) {
				rw.appCtx.Logger.Warn("X-Accel-Redirect文件未找到", "path", cleanTargetPath)
				return
			} else if err != nil {
				rw.appCtx.Logger.Error("访问X-Accel-Redirect文件错误", "path", cleanTargetPath, "error", err)
				return
			}

			var sharedLimiter *RedisCellLimiter
			if rw.accelTokenID != "" && rw.accelLimitBytes > 0 {
				limiter, err := GetOrCreateLimiter(rw.appCtx, rw.accelTokenID, int64(rw.accelLimitBytes))
				if err != nil {
					// 如果 Redis 未初始化或 GetOrCreateLimiter 失败，记录错误
					rw.appCtx.Logger.Error("无法获取带宽限制器，将不进行限制", "token_id", rw.accelTokenID, "error", err)
				} else {
					rw.appCtx.Logger.Debug("获取或创建带宽限制器", "token_id", rw.accelTokenID, "limit_bytes", rw.accelLimitBytes)
					sharedLimiter = limiter
				}
			}

			sendFileWithSendfile(rw.appCtx, r.Context(), rw, r, cleanTargetPath, fileInfo, sharedLimiter)
		}
	})
}

// handleTryFiles 尝试处理静态文件、目录或自定义错误页面。
// 如果请求被处理，则返回 true；否则返回 false，表示应继续处理 PHP。
func handleTryFiles(appCtx *AppContext, w http.ResponseWriter, r *http.Request) bool {
	requestPath := r.URL.Path

	if strings.HasSuffix(requestPath, ".php") {
		return false
	}

	filePath := filepath.Join(appCtx.Config.DocRoot, requestPath)

	fileInfo, err := os.Stat(filePath)
	if err == nil {
		if fileInfo.IsDir() {
			appCtx.Logger.Debug("tryFiles 匹配到目录，返回 403", "path", filePath)
			return true
		}
		appCtx.Logger.Debug("tryFiles 匹配到文件，直接提供", "path", filePath)
		http.ServeFile(w, r, filePath)
		return true
	}

	if os.IsNotExist(err) {
		appCtx.Logger.Debug("tryFiles 未匹配到任何静态资源，转交 PHP 处理", "request_path", requestPath)
		return false
	}

	appCtx.Logger.Error("tryFiles 检查文件/目录时出错", "path", filePath, "error", err)
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

// sendFileWithSendfile 使用sendfile系统调用发送文件，并应用传入的令牌桶限速器
func sendFileWithSendfile(appCtx *AppContext, ctx context.Context, w *responseInterceptor, r *http.Request, filePath string,
	fileInfo os.FileInfo, limiter *RedisCellLimiter) {

	originalWriter := w.ResponseWriter
	originalWriter.Header().Set("Accept-Ranges", "bytes")

	etag := fmt.Sprintf("%d-%d", fileInfo.ModTime().UnixNano(), fileInfo.Size())
	originalWriter.Header().Set("ETag", etag)

	var startRange int64 = 0
	var endRange int64 = fileInfo.Size() - 1
	var isPartialRequest bool = false

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		// 解析 Range 头
		ranges, err := parseRangeHeader(rangeHeader, fileInfo.Size())
		if err != nil {
			http.Error(originalWriter, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
			return
		}

		// 仅处理第一个范围
		if len(ranges) > 0 {
			startRange = ranges[0].start
			endRange = ranges[0].end
			isPartialRequest = true

			originalWriter.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d",
				startRange, endRange, fileInfo.Size()))
		}
	}

	// 准备 TCP 连接 hijack
	hijacker, ok := originalWriter.(http.Hijacker)
	if !ok {
		appCtx.Logger.Error("ResponseWriter不支持Hijacker接口")
		return
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		appCtx.Logger.Error("无法劫持连接", "error", err)
		return
	}
	defer conn.Close()

	// 转换为 TCP 连接
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		appCtx.Logger.Error("劫持的连接不是TCP连接")
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		appCtx.Logger.Error("打开文件错误", "path", filePath, "error", err)
		return
	}
	defer file.Close()

	if isPartialRequest {
		_, err = file.Seek(startRange, io.SeekStart)
		if err != nil {
			appCtx.Logger.Error("定位文件范围起始错误", "offset", startRange, "error", err)
			return
		}
	}

	tcpFile, err := tcpConn.File()
	if err != nil {
		appCtx.Logger.Error("获取TCP文件描述符错误", "error", err)
		return
	}
	defer tcpFile.Close()

	var respStatus string
	var contentLength int64
	if isPartialRequest {
		respStatus = "HTTP/1.1 206 Partial Content\r\n"
		contentLength = endRange - startRange + 1
	} else {
		respStatus = "HTTP/1.1 200 OK\r\n"
		contentLength = fileInfo.Size()
	}

	bufrw.WriteString(respStatus)
	bufrw.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLength))

	// 写入响应头
	err = originalWriter.Header().Write(bufrw)
	if err != nil {
		appCtx.Logger.Error("写入头信息到劫持连接错误", "error", err)
		return
	}

	bufrw.WriteString("\r\n")
	bufrw.Flush()

	logAttrs := []any{"path", filePath}
	if isPartialRequest {
		logAttrs = append(logAttrs, "range_start", startRange, "range_end", endRange)
	}
	appCtx.Logger.Info("通过X-Accel-Redirect使用sendfile服务文件", logAttrs...)

	srcFd := int(file.Fd())
	dstFd := int(tcpFile.Fd())

	bytesToSend := endRange - startRange + 1
	sentBytes := int64(0)

	// 分块发送文件，应用限速器
	for sentBytes < bytesToSend {
		chunkSize := int(math.Min(float64(bytesToSend-sentBytes), float64(1<<18))) // 最大 256KB

		if limiter != nil {
			waitErr := limiter.WaitN(ctx, int64(chunkSize))
			if waitErr != nil {
				appCtx.Logger.Warn("速率限制器等待错误，停止传输", "error", waitErr)
				break
			}
		}

		n, sendErr := syscall.Sendfile(dstFd, srcFd, nil, chunkSize)
		if sendErr != nil {
			// 处理 sendfile 错误
			if se, ok := sendErr.(syscall.Errno); ok && se == syscall.EPIPE {
				appCtx.Logger.Warn("Sendfile错误: 管道破裂(客户端可能已断开连接)")
			} else {
				appCtx.Logger.Error("sendfile过程中错误", "error", sendErr)
			}
			break
		}
		if n == 0 {
			appCtx.Logger.Info("sendfile返回0字节，传输完成或连接关闭")
			break
		}
		sentBytes += int64(n)
	}

	appCtx.Logger.Info("完成sendfile传输", "path", filePath, "sent_bytes", sentBytes)
}

type byteRange struct {
	start int64
	end   int64
}

// parseRangeHeader 解析 HTTP Range 头，返回请求的范围列表
func parseRangeHeader(rangeHeader string, fileSize int64) ([]byteRange, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("unsupported range unit")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")

	var ranges []byteRange
	for _, r := range strings.Split(rangeSpec, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		i := strings.IndexByte(r, '-')
		if i < 0 {
			return nil, fmt.Errorf("invalid range format: %s", r)
		}

		startStr := r[:i]
		endStr := r[i+1:]

		var startByte, endByte int64
		var err error

		if startStr == "" {
			// 后缀范围: -N
			if endStr == "" {
				return nil, fmt.Errorf("invalid suffix range format: %s", r)
			}
			suffixLen, err := strconv.ParseInt(endStr, 10, 64)
			if err != nil || suffixLen <= 0 {
				return nil, fmt.Errorf("invalid suffix length: %s", endStr)
			}
			if suffixLen > fileSize {
				suffixLen = fileSize
			}
			startByte = fileSize - suffixLen
			endByte = fileSize - 1
		} else {
			// 起始范围: M-N 或 M-
			startByte, err = strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range start: %s", startStr)
			}

			if endStr == "" {
				// M-: 到结尾
				endByte = fileSize - 1
			} else {
				// M-N: 到 N
				endByte, err = strconv.ParseInt(endStr, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid range end: %s", endStr)
				}
			}
		}

		if startByte < 0 {
			startByte = 0
		}

		if endByte < startByte || endByte >= fileSize {
			endByte = fileSize - 1
		}

		// 调整结束位置
		if startByte > endByte || startByte >= fileSize {
			continue
		}

		ranges = append(ranges, byteRange{start: startByte, end: endByte})
	}

	if len(ranges) == 0 {
		// 无有效范围
		return nil, fmt.Errorf("range not satisfiable")
	}

	// 注意: 仅处理第一个有效范围
	return ranges, nil
}
