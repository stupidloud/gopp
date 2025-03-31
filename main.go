package main

import (
	"fmt" // 需要保留 fmt 用于错误格式化
	"log/slog"
	"net/http"
	"os"      // 需要 os.Stdout 和 os.Exit
	"strings" // 用于日志级别字符串处理
	"time"

	"github.com/yookoala/gofast"
)

// 全局配置变量（如果愿意，可考虑显式传递）
var config Config
var logger *slog.Logger // 全局 logger 实例

// parseLogLevel 将字符串日志级别转换为 slog.Level
func parseLogLevel(levelStr string) slog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		// 如果配置无效，默认使用 Info 级别并打印警告
		fmt.Fprintf(os.Stderr, "警告：无效的日志级别 '%s'，将使用 'info' 级别\n", levelStr)
		return slog.LevelInfo
	}
}

func main() {
	var err error
	// 使用 config.go 中的函数加载配置
	config, err = loadConfig("config.yaml")
	if err != nil {
		// loadConfig 现在在文件未找到时返回默认配置，
		// 因此此错误可能是解析问题导致的。
		// 使用 fmt 输出到 stderr，因为 logger 可能尚未初始化
		fmt.Fprintf(os.Stderr, "警告：无法加载或解析 config.yaml：%v。使用默认配置。\n", err)
		// 当loadConfig返回错误时，config已经包含defaultConfig
	}

	// --- 初始化日志 ---
	logLevel := parseLogLevel(config.LogLevel)
	// 使用 TextHandler 输出到标准输出，可以根据需要换成 JSONHandler 或其他 Handler
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	logger = slog.New(logHandler)
	// 可选：设置标准 log 包使用 slog (如果仍有地方直接用 log)
	// log.SetOutput(logger.Writer())
	// log.SetFlags(0) // slog 会处理时间戳等

	logger.Info("日志系统初始化完成", "level", logLevel.String())
	// --- 日志初始化完成 ---

	// 将超时时间转换为 time.Duration
	readTimeout := time.Duration(config.ReadTimeoutSeconds) * time.Second
	writeTimeout := time.Duration(config.WriteTimeoutSeconds) * time.Second
	idleTimeout := time.Duration(config.IdleTimeoutSeconds) * time.Second

	logger.Info("启动 HTTP 代理服务器", "address", config.ListenAddr)
	logger.Info("后端 PHP-FPM", "network", config.FPMNetwork, "address", config.FPMAddress)
	logger.Info("文档根目录", "path", config.DocRoot)
	logger.Info("X-Accel 根目录", "path", config.AccelRoot)
	logger.Info("主 PHP 文件", "file", config.MainPHPFile) // 记录正在使用的主 PHP 文件

	// 创建连接工厂
	connFactory := gofast.SimpleConnFactory(config.FPMNetwork, config.FPMAddress)

	// --- 创建速率限制后端 ---
	var backend RateLimiterBackend // 声明接口类型变量
	var backendErr error

	if config.RedisBackend {
		logger.Info("配置使用 Redis 后端进行速率限制")
		// 尝试创建 Redis 后端，让它自己管理连接 (传入 nil client)
		redisBackend, err := NewRedisBackend(&config, nil, logger) // 传递 logger
		if err != nil {
			logger.Warn("无法初始化 Redis 后端，将回退到内存后端", "error", err)
			backend = NewMemoryBackend(logger) // 回退到内存, 传递 logger
			logger.Info("已回退到内存后端进行速率限制")
		} else {
			backend = redisBackend // 使用 Redis 后端
			logger.Info("成功初始化 Redis 后端")
		}
	} else {
		logger.Info("配置使用内存后端进行速率限制")
		backend = NewMemoryBackend(logger) // 使用内存后端, 传递 logger
	}
	// --- 后端创建完毕 ---

	// 创建令牌桶管理器，传入配置、创建好的后端和 logger
	tokenManager, backendErr := NewTokenBucketManager(&config, backend, logger) // 传递 logger
	if backendErr != nil {
		// 如果 NewTokenBucketManager 出错（例如 backend 为 nil），则致命错误
		logger.Error("无法创建令牌桶管理器", "error", backendErr)
		os.Exit(1) // 替换 log.Fatalf
	}
	// 程序结束时关闭令牌桶管理器（这将关闭其使用的后端）
	defer func() {
		logger.Info("正在关闭令牌桶管理器...")
		if err := tokenManager.Close(); err != nil {
			logger.Error("关闭令牌桶管理器时出错", "error", err)
		} else {
			logger.Info("令牌桶管理器已关闭")
		}
	}()

	// 创建处理器（来自 handler.go）
	// 显式传递配置值和令牌桶管理器
	phpHandler := createPHPHandler(
		connFactory,
		config.DocRoot,
		config.AccelRoot,
		config.MainPHPFile,    // 从配置传递主PHP文件
		tokenManager,          // 传递令牌管理器实例
		config.TrustedProxies, // 传递可信代理列表
		logger,                // 将 logger 传递给 handler
	)

	// 创建服务器
	server := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      phpHandler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// 启动服务器
	logger.Info("服务器启动中...")
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		logger.Error("无法在指定地址监听", "address", config.ListenAddr, "error", err)
		os.Exit(1) // 替换 log.Fatalf
	}

	logger.Info("服务器已优雅停止")
}
