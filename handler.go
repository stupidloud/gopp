package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"mime"
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

// createPHPHandler 创建处理PHP请求的HTTP处理器
// 接受mainPHPFile和manager作为参数，而不是依赖全局变量
func createPHPHandler(connFactory gofast.ConnFactory, docRoot, accelRoot, mainPHPFile string, manager *TokenBucketManager) http.Handler {
	// 创建客户端工厂
	clientFactory := gofast.SimpleClientFactory(connFactory)

	// 使用传入的令牌桶管理器

	// 创建会话处理器，总是将请求路由到docRoot/mainPHPFile
	alwaysIndexSessionHandler := gofast.Chain(
		gofast.BasicParamsMap,
		gofast.MapHeader,
		gofast.MapRemoteHost,
		func(inner gofast.SessionHandler) gofast.SessionHandler {
			return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
				// 设置必要的FastCGI参数
				req.Params["DOCUMENT_ROOT"] = docRoot
				// 显式设置脚本为docRoot下从参数读取的mainPHPFile
				req.Params["SCRIPT_FILENAME"] = filepath.Join(docRoot, mainPHPFile)
				// SCRIPT_NAME通常是相对于DOCUMENT_ROOT的路径
				req.Params["SCRIPT_NAME"] = "/" + mainPHPFile
				// REQUEST_URI应保持原始请求URI(例如/123.zip)
				// gofast.BasicParamsMap会处理这个以及QUERY_STRING, REQUEST_METHOD等
				log.Printf("路由请求 %s 到 SCRIPT_FILENAME: %s", req.Params["REQUEST_URI"], req.Params["SCRIPT_FILENAME"])
				return inner(client, req)
			}
		},
	)(gofast.BasicSession) // BasicSession处理实际的FastCGI通信

	// 创建主处理器，使用我们修改过的会话处理器
	phpFSHandler := gofast.NewHandler(
		alwaysIndexSessionHandler, // 使用总是指向mainPHPFile的处理器
		clientFactory,
	)

	// 包装处理器，处理X-Accel-Redirect并添加限速
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 创建自定义的ResponseWriter用于捕获响应
		rw := &responseInterceptor{
			ResponseWriter: w,
			headersSent:    false,
			accelPath:      "",
		}

		phpFSHandler.ServeHTTP(rw, r)

		// 如果需要X-Accel-Redirect，则处理
		if rw.accelPath != "" {
			log.Printf("处理 X-Accel-Redirect: %s 对应请求 %s", rw.accelPath, r.URL.Path)

			targetPath := filepath.Join(accelRoot, rw.accelPath)
			cleanAccelRoot, _ := filepath.Abs(accelRoot)
			cleanTargetPath, _ := filepath.Abs(targetPath)

			if !filepath.HasPrefix(cleanTargetPath, cleanAccelRoot) {
				log.Printf("安全警告: 阻止X-Accel-Redirect路径遍历尝试: %s", rw.accelPath)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Check if file exists
			fileInfo, err := os.Stat(cleanTargetPath)
			if os.IsNotExist(err) {
				log.Printf("X-Accel-Redirect文件未找到: %s", cleanTargetPath)
				http.NotFound(w, r)
				return
			} else if err != nil {
				log.Printf("访问X-Accel-Redirect文件 %s 错误: %v", cleanTargetPath, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Add any headers from PHP that we want to pass through
			// (like Content-Disposition for downloads)
			// Pass the original ResponseWriter's Header() to copyHeaders
			copyHeaders(w.Header(), rw.Header()) // Copy PHP headers to original writer's headers

			// 获取或创建共享的 RateLimiter (使用传入的 manager)
			var sharedLimiter *RateLimiter
			// 使用从 header 中获取的 accelLimitBytes
			if rw.accelTokenID != "" && rw.accelLimitBytes > 0 { // 仅当同时提供了有效的 Token ID 和 Limit 时才创建/获取限速器
				manager.mu.Lock()
				limiter, exists := manager.limiters[rw.accelTokenID]
				if !exists {
					// 如果令牌桶不存在，则创建一个新的
					limit := rate.Limit(rw.accelLimitBytes) // bytes/s
					burst := int(limit)                     // Adjusted burst size according to new rate unit
					limiter = NewRateLimiter(limit, burst)
					manager.limiters[rw.accelTokenID] = limiter
					log.Printf("为令牌ID '%s'创建新的共享速率限制器: %d 字节/秒", rw.accelTokenID, rw.accelLimitBytes)
				} else {
					// 注意：这里没有更新现有令牌桶的速率。如果需要动态更新速率，需要额外逻辑。
					log.Printf("使用令牌ID '%s'的现有共享速率限制器", rw.accelTokenID)
				}
				sharedLimiter = limiter // 使用找到或创建的限速器
				manager.mu.Unlock()
			}
			// 如果没有提供 Token ID 或有效的 Limit，sharedLimiter 将保持为 nil，表示不限速

			// 调用统一的文件发送函数，传递获取到的限速器 (可能为 nil)
			// Directly pass rw (*responseInterceptor) as required by the function signature
			sendFileWithSendfile(r.Context(), rw, r, cleanTargetPath, fileInfo, sharedLimiter)
		}
		// 否则：正常响应已由responseInterceptor写入原始ResponseWriter处理
	})
}

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
				log.Printf("收到X-Accel-Limit-Rate: %d 字节/秒 对应令牌ID: %s", limit, tokenID)
			} else {
				log.Printf("警告: 收到无效的X-Accel-Limit-Rate值 '%s'。忽略令牌ID %s 的速率限制", limitStr, tokenID)
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
func sendFileWithSendfile(ctx context.Context, w *responseInterceptor, r *http.Request, filePath string,
	fileInfo os.FileInfo, limiter *RateLimiter) {

	// 设置基本响应头
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	originalWriter := w.ResponseWriter
	originalWriter.Header().Set("Content-Type", contentType)
	originalWriter.Header().Set("Accept-Ranges", "bytes")

	// 处理 Range 请求
	var startRange int64 = 0
	var endRange int64 = fileInfo.Size() - 1 // Initialize endRange correctly
	var isPartialRequest bool = false

	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		// 解析 Range 头 (例如 "bytes=0-1023")
		// Removed duplicated declarations inside the block
		ranges, err := parseRangeHeader(rangeHeader, fileInfo.Size())
		if err != nil {
			// Use original writer for error before hijack
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
		log.Printf("错误: ResponseWriter不支持Hijacker接口")
		http.Error(originalWriter, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Error: Failed to hijack connection: %v", err)
		// 无法发送 HTTP 错误，因为连接可能已损坏
		return
	}
	defer conn.Close()

	// 转换为 TCP 连接 (在Linux上，这应该总是成功的)
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		log.Printf("错误: 劫持的连接不是TCP连接")
		// Try to write error to buffer, might fail
		bufrw.WriteString("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\nInternal Server Error: Not a TCP connection")
		bufrw.Flush()
		return
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("打开文件 %s 错误: %v", filePath, err)
		// 已经 hijack 了连接，需要手动写入响应
		bufrw.WriteString("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\nError opening file")
		bufrw.Flush()
		return
	}
	defer file.Close()

	// 如果是部分请求，定位到正确的位置
	if isPartialRequest {
		_, err = file.Seek(startRange, io.SeekStart)
		if err != nil {
			log.Printf("定位到范围起始 %d 错误: %v", startRange, err)
			bufrw.WriteString("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\nError seeking file")
			bufrw.Flush()
			return
		}
	}

	// 获取 TCP 连接的文件描述符
	tcpFile, err := tcpConn.File()
	if err != nil {
		log.Printf("获取TCP文件描述符错误: %v", err)
		bufrw.WriteString("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\nError getting TCP descriptor")
		bufrw.Flush()
		return
	}
	defer tcpFile.Close()

	// RateLimiter(limiter)现在作为参数传入

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
		log.Printf("写入头信息到劫持连接错误: %v", err)
		return // Cannot proceed
	}

	// 结束头信息
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	logMsg := fmt.Sprintf("通过X-Accel-Redirect使用sendfile服务文件: %s", filePath)

	if isPartialRequest {
		logMsg += fmt.Sprintf(" (range %d-%d)", startRange, endRange)
	}
	log.Print(logMsg)

	// 使用 sendfile 发送文件
	srcFd := int(file.Fd())
	dstFd := int(tcpFile.Fd())

	bytesToSend := endRange - startRange + 1
	sentBytes := int64(0)

	// 分块发送文件，每块不超过 1MB，并应用传入的限速器（如果存在）
	for sentBytes < bytesToSend {
		// 确定本次发送的块大小
		chunkSize := int(min(bytesToSend-sentBytes, int64(1<<19))) // 512k 块或剩余全部

		// 如果传入了限速器 (limiter != nil)，则等待令牌
		if limiter != nil {
			// 等待发送 chunkSize 字节所需的令牌
			// Wait 会阻塞直到获得令牌或上下文被取消
			waitErr := limiter.Wait(ctx, chunkSize) // 使用传入的 limiter
			if waitErr != nil {
				// 如果上下文被取消（例如，客户端断开连接）或发生其他错误，则停止发送
				log.Printf("速率限制器等待错误: %v。停止传输。", waitErr)
				break
			}
		}

		// 使用 sendfile 发送数据块
		n, sendErr := syscall.Sendfile(dstFd, srcFd, nil, chunkSize) // 使用 nil 让内核自动处理文件偏移量
		if sendErr != nil {
			// 处理 sendfile 错误（例如，连接断开）
			if se, ok := sendErr.(syscall.Errno); ok && se == syscall.EPIPE {
				log.Printf("Sendfile错误: 管道破裂(客户端可能已断开连接)")
			} else {
				log.Printf("sendfile过程中错误: %v", sendErr)
			}
			break // 发生错误，停止传输
		}
		if n == 0 {
			// sendfile 返回 0 通常意味着没有更多数据可发送或连接已关闭
			log.Print("sendfile返回0字节，假设EOF或连接已关闭")
			break // 假设传输完成或中断
		}
		// 更新已发送的字节数
		sentBytes += int64(n)
	}

	log.Printf("完成sendfile传输 %s: 已发送 %d 字节", filePath, sentBytes)
}

// clamp 限制一个整数在指定范围内
func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// min 返回两个 int64 中较小的一个
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// copyHeaders从src复制头信息到dst，排除hop-by-hop和X-Accel头
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		// 规范化header key以便比较
		normalizedKey := http.CanonicalHeaderKey(k)
		// 不要复制hop-by-hop头或特定的X-Accel头
		if normalizedKey == "Connection" ||
			normalizedKey == "Keep-Alive" ||
			normalizedKey == "Proxy-Authenticate" ||
			normalizedKey == "Proxy-Authorization" ||
			normalizedKey == "Te" || // canonicalized version of "TE"
			normalizedKey == "Trailers" ||
			normalizedKey == "Transfer-Encoding" ||
			normalizedKey == "Upgrade" ||
			normalizedKey == "X-Accel-Redirect" ||
			normalizedKey == "X-Accel-Limit-Rate" ||
			normalizedKey == "X-Accel-Token-Id" {
			continue
		}
		// 添加剩余的头信息
		for _, v := range vv {
			dst.Add(k, v) // 使用Add处理同一header的多个值
		}
	}
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
