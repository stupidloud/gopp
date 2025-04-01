package main

import (
	"context"
	"fmt"
	"io"
	"log/slog" // 替换 log
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/yookoala/gofast"
	"golang.org/x/time/rate" // 保留rate导入用于RateLimiter类型
)

// GetRealIP 从请求中获取真实的客户端IP地址
// 如果请求来自可信代理，会检查X-Forwarded-For头
func GetRealIP(r *http.Request, trustedProxies []string) string {
	// 首先获取直接连接的IP地址
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 如果无法解析RemoteAddr，则直接返回原始值
		return r.RemoteAddr
	}

	// 检查是否来自可信代理
	isTrusted := false
	for _, proxy := range trustedProxies {
		if proxy == ip {
			isTrusted = true
			break
		}
		// 支持CIDR格式
		if strings.Contains(proxy, "/") {
			_, ipnet, cidrErr := net.ParseCIDR(proxy)
			if cidrErr == nil && ipnet.Contains(net.ParseIP(ip)) {
				isTrusted = true
				break
			}
		}
	}

	// 如果不是来自可信代理，直接返回连接IP
	if !isTrusted {
		return ip
	}

	// 处理X-Forwarded-For头
	// 格式通常是: client, proxy1, proxy2, ...
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// 拆分并获取最左边的IP（最原始的客户端）
		ips := strings.Split(forwardedFor, ",")
		clientIP := strings.TrimSpace(ips[0])
		if clientIP != "" {
			return clientIP
		}
	}

	// 如果X-Forwarded-For为空，尝试其他常见的代理头
	if clientIP := r.Header.Get("X-Real-IP"); clientIP != "" {
		return clientIP
	}

	// 所有尝试都失败，返回直接连接的IP
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

	// 连接路径
	targetPath := filepath.Join(cleanBasePath, requestedPath)

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
func phpScriptRouterSessionHandler(logger *slog.Logger, docRoot string, mainPHPFile string) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			requestPath := req.Raw.URL.Path
			scriptToExecute := mainPHPFile // 默认执行 mainPHPFile
			scriptName := "/" + mainPHPFile

			if strings.HasSuffix(requestPath, ".php") {
				// 如果请求的是 .php 文件，尝试执行该文件
				// 使用 secureJoinPath 进行路径拼接和安全检查
				cleanTargetPath, err := secureJoinPath(docRoot, requestPath)
				if err != nil {
					logger.Warn("安全路径检查失败", "requested_path", requestPath, "doc_root", docRoot, "error", err)
					// 返回更通用的错误，避免泄露内部路径结构
					return nil, fmt.Errorf("forbidden: invalid or disallowed path %s", requestPath)
				}
				requestedScriptPath := cleanTargetPath

				// 检查请求的 .php 文件是否存在
				if _, err := os.Stat(requestedScriptPath); err == nil {
					// 文件存在，设置执行此脚本
					scriptToExecute = requestPath // 使用相对路径
					scriptName = requestPath
				} else if os.IsNotExist(err) {
					// 文件不存在，返回 404 错误
					logger.Debug("请求的 .php 文件不存在", "requested_path", requestPath)
					return nil, fmt.Errorf("not found: script %s not found", requestPath)
				} else {
					// 其他 Stat 错误
					logger.Error("检查请求的 .php 文件时出错", "path", requestedScriptPath, "error", err)
					return nil, fmt.Errorf("internal server error checking script %s", requestPath)
				}
			}
			// else: 请求的不是 .php 文件，使用默认的 mainPHPFile

			// 设置最终确定的脚本参数
			req.Params["SCRIPT_FILENAME"] = filepath.Join(docRoot, scriptToExecute)
			req.Params["SCRIPT_NAME"] = scriptName
			logger.Debug("PHP 脚本路由", "script_filename", req.Params["SCRIPT_FILENAME"], "script_name", req.Params["SCRIPT_NAME"])

			return inner(client, req)
		}
	}
}

// basicFastCGISetupSessionHandler 设置基本的 FastCGI 参数，如 DOCUMENT_ROOT 和 REMOTE_ADDR。
func basicFastCGISetupSessionHandler(logger *slog.Logger, docRoot string, trustedProxies []string) func(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(inner gofast.SessionHandler) gofast.SessionHandler {
		return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
			// 设置 DOCUMENT_ROOT
			req.Params["DOCUMENT_ROOT"] = docRoot

			// 获取并设置真实的客户端 IP (REMOTE_ADDR) 和代理头
			realIP := GetRealIP(req.Raw, trustedProxies)
			req.Params["REMOTE_ADDR"] = realIP
			if forwardedFor := req.Raw.Header.Get("X-Forwarded-For"); forwardedFor != "" {
				req.Params["HTTP_X_FORWARDED_FOR"] = forwardedFor
			}
			if realIPHeader := req.Raw.Header.Get("X-Real-IP"); realIPHeader != "" {
				req.Params["HTTP_X_REAL_IP"] = realIPHeader
			}
			logger.Debug("设置基本 FastCGI 参数", "doc_root", docRoot, "remote_addr", realIP)

			return inner(client, req)
		}
	}
}

// createPHPHandler 创建处理PHP请求的HTTP处理器
func createPHPHandler(logger *slog.Logger, connFactory gofast.ConnFactory, docRoot, accelRoot, mainPHPFile string, manager *TokenBucketManager, trustedProxies []string) http.Handler { // 重新加入 tryFiles 和 errorPages 参数
	clientFactory := gofast.SimpleClientFactory(connFactory)

	// 创建 FastCGI 会话处理器链
	phpSessionHandler := gofast.Chain(
		gofast.BasicParamsMap, // 处理基本 CGI 参数 (REQUEST_METHOD, QUERY_STRING, etc.)
		gofast.MapHeader,      // 映射 HTTP 请求头到 FastCGI (HTTP_*)
		gofast.MapRemoteHost,  // 设置 REMOTE_HOST (可能基于 REMOTE_ADDR)
		basicFastCGISetupSessionHandler(logger, docRoot, trustedProxies), // 设置 DOCUMENT_ROOT, REMOTE_ADDR 等
		phpScriptRouterSessionHandler(logger, docRoot, mainPHPFile),      // 动态设置 SCRIPT_FILENAME 和 SCRIPT_NAME
	)(gofast.BasicSession) // BasicSession 处理实际的 FastCGI 通信

	// 创建主处理器，使用我们修改过的会话处理器
	phpFSHandler := gofast.NewHandler(
		phpSessionHandler, // 使用包含路由逻辑的处理器链
		clientFactory,
	)

	// 包装处理器，处理X-Accel-Redirect并添加限速
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 尝试处理静态文件或目录 (如果 tryFiles 启用)
		handleTryFiles(logger, w, r, docRoot)

		// 如果未被 tryFiles 处理，则执行 PHP 请求
		// --- Start inlined processPHPRequest & handleAccelRedirect ---
		// 创建自定义的ResponseWriter用于捕获响应
		rw := &responseInterceptor{
			ResponseWriter: w,
			headersSent:    false,
			accelPath:      "",
			// accelTokenID and accelLimitBytes will be populated by WriteHeader
		}

		// 将请求传递给 PHP FastCGI 处理器
		phpFSHandler.ServeHTTP(rw, r) // Use phpFSHandler from outer scope

		// 如果 PHP 返回了 X-Accel-Redirect 头，则处理内部重定向
		if rw.accelPath != "" {
			// --- Start inlined handleAccelRedirect logic ---
			logger.Info("处理 X-Accel-Redirect", "accel_path", rw.accelPath, "request_uri", r.URL.Path)

			// 使用 secureJoinPath 进行路径拼接和安全检查
			cleanTargetPath, err := secureJoinPath(accelRoot, rw.accelPath)
			if err != nil {
				logger.Warn("X-Accel-Redirect 安全路径检查失败", "accel_path", rw.accelPath, "accel_root", accelRoot, "error", err)
				return
			}
			// 检查目标文件是否存在
			fileInfo, err := os.Stat(cleanTargetPath) // Use cleanTargetPath for Stat
			if os.IsNotExist(err) {
				logger.Warn("X-Accel-Redirect文件未找到", "path", cleanTargetPath)
				// Use the original ResponseWriter
				return
			} else if err != nil {
				logger.Error("访问X-Accel-Redirect文件错误", "path", cleanTargetPath, "error", err)
				// Use the original ResponseWriter
				return
			}

			// 获取或创建共享的 RateLimiter
			var sharedLimiter *RateLimiter
			if rw.accelTokenID != "" && rw.accelLimitBytes > 0 {
				// 检查 manager 是否为 nil
				if manager == nil { // Use manager from outer scope
					logger.Error("TokenBucketManager 未初始化，无法应用速率限制")
				} else {
					// Calculate burst based on limit (e.g., 1.5x limit)
					burst := int(float64(rw.accelLimitBytes) * 1.5)
					limiter := manager.GetLimiter(rw.accelTokenID, rate.Limit(rw.accelLimitBytes), burst)
					logger.Debug("获取或创建速率限制器", "token_id", rw.accelTokenID, "limit_bytes", rw.accelLimitBytes, "burst", burst)
					// Ensure the limiter has the latest settings (GetLimiter might create or update)
					limiter.SetLimit(rate.Limit(rw.accelLimitBytes))
					limiter.SetBurst(burst)
					sharedLimiter = limiter
				}
			}

			// 使用 sendfile 发送文件
			// Pass the interceptor (rw) which holds the original ResponseWriter
			sendFileWithSendfile(logger, r.Context(), rw, r, cleanTargetPath, fileInfo, sharedLimiter)
			// --- End inlined handleAccelRedirect logic ---
		}
		// --- End inlined processPHPRequest & handleAccelRedirect ---
	})
}

// handleTryFiles 尝试处理静态文件、目录或自定义错误页面。
// 如果请求被处理，则返回 true；否则返回 false，表示应继续处理 PHP。
func handleTryFiles(logger *slog.Logger, w http.ResponseWriter, r *http.Request, docRoot string) bool {
	requestPath := r.URL.Path

	// 如果请求的是 .php 文件，不由此函数处理，交给 PHP 处理器
	if strings.HasSuffix(requestPath, ".php") {
		return false
	}

	filePath := filepath.Join(docRoot, requestPath)

	// 检查文件是否存在
	fileInfo, err := os.Stat(filePath)
	if err == nil {
		if fileInfo.IsDir() {
			// 如果是目录，返回 403 Forbidden
			logger.Debug("tryFiles 匹配到目录，返回 403", "path", filePath)
			return true // 请求已处理
		}
		// 如果是文件，直接提供
		logger.Debug("tryFiles 匹配到文件，直接提供", "path", filePath)
		http.ServeFile(w, r, filePath)
		return true // 请求已处理
	}

	// 如果文件或目录不存在 (os.IsNotExist(err) is true)
	if os.IsNotExist(err) {
		// 没有匹配到任何东西，让 PHP 处理器处理 (可能生成动态 404 或路由)
		logger.Debug("tryFiles 未匹配到任何静态资源，转交 PHP 处理", "request_path", requestPath)
		return false
	}

	// 其他 Stat 错误 (例如权限问题)
	logger.Error("tryFiles 检查文件/目录时出错", "path", filePath, "error", err)
	return true // 请求已处理 (返回错误)
}

// processPHPRequest 和 handleAccelRedirect 函数已被内联到 createPHPHandler 中

// responseInterceptor 是一个拦截响应的自定义ResponseWriter
type responseInterceptor struct {
	http.ResponseWriter
	headersSent     bool
	accelPath       string
	accelTokenID    string // 存储令牌桶ID
	accelLimitBytes int    // 新增字段，用于存储速率限制 (字节/s)，0表示未指定或无效
}

// WriteHeader 拦截WriteHeader调用以检测X-Accel-Redirect和X-Accel-Token-Id
func (rw *responseInterceptor) WriteHeader(code int) {
	if rw.headersSent {
		return
	}

	// 检查 X-Accel-Redirect
	accelPath := rw.Header().Get("X-Accel-Redirect")
	if accelPath != "" {
		rw.accelPath = accelPath
		rw.Header().Del("X-Accel-Redirect") // 从最终响应中移除

		// 检查 X-Accel-Token-Id (只有在 X-Accel-Redirect 存在时才有意义)
		tokenID := rw.Header().Get("X-Accel-Token-Id")
		if tokenID != "" {
			rw.accelTokenID = tokenID
			rw.Header().Del("X-Accel-Token-Id") // 从最终响应中移除
		}
		// 检查 X-Accel-Limit-Rate (单位:字节)
		limitStr := rw.Header().Get("X-Accel-Limit-Rate")
		if limitStr != "" {
			limit, err := strconv.Atoi(limitStr)
			if err == nil && limit > 0 {
				rw.accelLimitBytes = limit // 存储有效的速率限制(字节)
				logger.Debug("收到 X-Accel-Limit-Rate", "limit_bytes", limit, "token_id", tokenID)
			} else {
				logger.Warn("收到无效的 X-Accel-Limit-Rate 值，忽略速率限制", "value", limitStr, "token_id", tokenID)
			}
			rw.Header().Del("X-Accel-Limit-Rate") // 从最终响应中移除
		}

		// 不要立即写入头，让外部处理器决定
		return
	}

	// 如果没有 X-Accel-Redirect，则正常写入头
	rw.ResponseWriter.WriteHeader(code)
	rw.headersSent = true
}

// Write 拦截Write调用
func (rw *responseInterceptor) Write(b []byte) (int, error) {
	if rw.accelPath != "" {
		// 如果X-Accel-Redirect激活则丢弃响应体
		return len(b), nil
	}
	if !rw.headersSent {
		rw.WriteHeader(http.StatusOK) // 确保在发送响应体前发送头信息
	}
	return rw.ResponseWriter.Write(b)
}

// Flush 实现http.Flusher接口
func (rw *responseInterceptor) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok && rw.headersSent {
		flusher.Flush()
	}
}

// sendFileWithSendfile 使用sendfile系统调用发送文件，并应用传入的令牌桶限速器
func sendFileWithSendfile(logger *slog.Logger, ctx context.Context, w *responseInterceptor, r *http.Request, filePath string,
	fileInfo os.FileInfo, limiter *RateLimiter) { // 添加 logger 参数

	originalWriter := w.ResponseWriter
	originalWriter.Header().Set("Accept-Ranges", "bytes")

	// 计算并设置etag
	etag := fmt.Sprintf("%d-%d", fileInfo.ModTime().UnixNano(), fileInfo.Size())
	originalWriter.Header().Set("ETag", etag)

	// 处理 Range 请求
	var startRange int64 = 0
	var endRange int64 = fileInfo.Size() - 1 // Initialize endRange correctly
	var isPartialRequest bool = false

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		// 解析 Range 头 (例如 "bytes=0-1023")
		// Removed duplicated declarations inside the block
		ranges, err := parseRangeHeader(rangeHeader, fileInfo.Size())
		if err != nil {
			http.Error(originalWriter, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
			return
		}

		// 为简化处理，我们只处理第一个范围（如果指定了多个）
		if len(ranges) > 0 {
			startRange = ranges[0].start
			endRange = ranges[0].end
			isPartialRequest = true

			// Set Content-Range on the original writer's headers
			originalWriter.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d",
				startRange, endRange, fileInfo.Size()))
		}
	}

	// 为 TCP 连接准备 hijack (在Linux上，这应该总是可行的)
	hijacker, ok := originalWriter.(http.Hijacker)
	if !ok {
		logger.Error("ResponseWriter不支持Hijacker接口")
		return
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		logger.Error("无法劫持连接", "error", err)
		return
	}
	defer conn.Close()

	// 转换为 TCP 连接 (在Linux上，这应该总是成功的)
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		logger.Error("劫持的连接不是TCP连接")
		return
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("打开文件错误", "path", filePath, "error", err)
		return
	}
	defer file.Close()

	// 如果是部分请求，定位到正确的位置
	if isPartialRequest {
		_, err = file.Seek(startRange, io.SeekStart)
		if err != nil {
			logger.Error("定位文件范围起始错误", "offset", startRange, "error", err)
			return
		}
	}

	// 获取 TCP 连接的文件描述符
	tcpFile, err := tcpConn.File()
	if err != nil {
		logger.Error("获取TCP文件描述符错误", "error", err)
		return
	}
	defer tcpFile.Close()

	// 准备 HTTP 响应头
	var respStatus string
	var contentLength int64
	if isPartialRequest {
		respStatus = "HTTP/1.1 206 Partial Content\r\n"
		contentLength = endRange - startRange + 1
		// Content-Range头信息已在originalWriter上设置
	} else {
		respStatus = "HTTP/1.1 200 OK\r\n"
		contentLength = fileInfo.Size()
	}

	// 写入状态行
	bufrw.WriteString(respStatus)

	// 写入计算后的Content-Length
	bufrw.WriteString(fmt.Sprintf("Content-Length: %d\r\n", contentLength))

	// 从原始ResponseWriter写入头信息(包括Content-Type、Accept-Ranges、Content-Range(如果设置)和PHP头)
	err = originalWriter.Header().Write(bufrw)
	if err != nil {
		logger.Error("写入头信息到劫持连接错误", "error", err)
		return // Cannot proceed
	}

	// 结束头信息
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	logAttrs := []any{"path", filePath}
	if isPartialRequest {
		logAttrs = append(logAttrs, "range_start", startRange, "range_end", endRange)
	}
	logger.Info("通过X-Accel-Redirect使用sendfile服务文件", logAttrs...)

	// 使用 sendfile 发送文件
	srcFd := int(file.Fd())
	dstFd := int(tcpFile.Fd())

	bytesToSend := endRange - startRange + 1
	sentBytes := int64(0)

	// 分块发送文件，每块不超过 256KB，并应用传入的限速器（如果存在）
	for sentBytes < bytesToSend {
		// 确定本次发送的块大小
		chunkSize := int(math.Min(float64(bytesToSend-sentBytes), float64(1<<18))) // 256k 块或剩余全部

		// 如果传入了限速器 (limiter != nil)，则等待令牌
		if limiter != nil {
			// 等待发送 chunkSize 字节所需的令牌
			// Wait 会阻塞直到获得令牌或上下文被取消
			waitErr := limiter.Wait(ctx, chunkSize) // 使用传入的 limiter
			if waitErr != nil {
				// 如果上下文被取消（例如，客户端断开连接）或发生其他错误，则停止发送
				logger.Warn("速率限制器等待错误，停止传输", "error", waitErr)
				break
			}
		}

		// 使用 sendfile 发送数据块
		n, sendErr := syscall.Sendfile(dstFd, srcFd, nil, chunkSize) // 使用 nil 让内核自动处理文件偏移量
		if sendErr != nil {
			// 处理 sendfile 错误（例如，连接断开）
			if se, ok := sendErr.(syscall.Errno); ok && se == syscall.EPIPE {
				logger.Warn("Sendfile错误: 管道破裂(客户端可能已断开连接)")
			} else {
				logger.Error("sendfile过程中错误", "error", sendErr)
			}
			break // 发生错误，停止传输
		}
		if n == 0 {
			// sendfile 返回 0 通常意味着没有更多数据可发送或连接已关闭
			logger.Info("sendfile返回0字节，假设EOF或连接已关闭")
			break // 假设传输完成或中断
		}
		// 更新已发送的字节数
		sentBytes += int64(n)
	}

	logger.Info("完成sendfile传输", "path", filePath, "sent_bytes", sentBytes)
}

// Range 表示 HTTP 范围请求中的字节范围
type byteRange struct {
	start int64
	end   int64
}

// parseRangeHeader 解析 HTTP Range 头，返回请求的范围列表
func parseRangeHeader(rangeHeader string, fileSize int64) ([]byteRange, error) {
	// 检查前缀
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("unsupported range unit")
	}

	// 移除"bytes="前缀
	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")

	// 解析每个范围（以逗号分隔）
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
			// 后缀范围: -N (最后N字节)
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
			// 带起始的范围: M-N 或 M-
			startByte, err = strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid range start: %s", startStr)
			}

			if endStr == "" {
				// M-: 从M到结尾
				endByte = fileSize - 1
			} else {
				// M-N: 从M到N(包含)
				endByte, err = strconv.ParseInt(endStr, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid range end: %s", endStr)
				}
			}
		}

		// 验证范围起始
		if startByte < 0 {
			startByte = 0 // Treat negative start as 0
		}

		// 验证范围结束并在必要时调整
		if endByte < startByte || endByte >= fileSize {
			endByte = fileSize - 1
		}

		// 最终检查: 如果调整后起始超过结束或>=文件大小，则无法满足
		if startByte > endByte || startByte >= fileSize {
			continue // Skip this unsatisfiable range part
		}

		ranges = append(ranges, byteRange{start: startByte, end: endByte})
	}

	if len(ranges) == 0 {
		// 当所有范围部分都无效/无法满足时发生
		return nil, fmt.Errorf("range not satisfiable")
	}

	// 注意: 此实现不处理重叠/未排序的范围或多部分响应
	// 如果指定了多个范围，它只处理第一个有效的范围
	return ranges, nil
}
