package main

import (
	"fmt" // 需要保留 fmt 用于错误格式化
	"log/slog"
	"net/http"
	"os"      // 需要 os.Stdout 和 os.Exit
	"strings" // 用于日志级别字符串处理
	"time"

	"github.com/go-redis/redis/v8" // 引入 redis 客户端

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

	readTimeout := time.Duration(config.ReadTimeoutSeconds) * time.Second
	writeTimeout := time.Duration(config.WriteTimeoutSeconds) * time.Second
	idleTimeout := time.Duration(config.IdleTimeoutSeconds) * time.Second

	logger.Info("启动 HTTP 代理服务器", "address", config.ListenAddr)
	logger.Info("后端 PHP-FPM", "network", config.FPMNetwork, "address", config.FPMAddress)
	logger.Info("文档根目录", "path", config.DocRoot)
	logger.Info("X-Accel 根目录", "path", config.AccelRoot)
	logger.Info("主 PHP 文件", "file", config.MainPHPFile) // 记录正在使用的主 PHP 文件

	connFactory := gofast.SimpleConnFactory(config.FPMNetwork, config.FPMAddress)

	// --- 初始化带宽管理器 ---
	if config.RedisBackend {
		logger.Info("配置使用 Redis 后端进行带宽限制")
		redisOpts := &redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		}
		err := InitBandwidthManager(redisOpts)
		if err != nil {
			logger.Error("无法初始化 Redis 带宽管理器", "error", err)
			os.Exit(1) // 初始化失败则退出
		} else {
			logger.Info("成功初始化 Redis 带宽管理器")
		}
	} else {
		logger.Info("未配置 Redis 后端，带宽限制功能将不可用")
		// 注意：如果未配置 Redis，GetOrCreateLimiter 将无法工作，
		// handler 中需要处理 managerRedisClient 为 nil 的情况，
		// 或者在此处提供一个空操作的 Limiter 实现。
		// 当前 bandwidth_manager 实现会在未初始化时 panic 或返回错误。
		// 为了简单起见，如果未配置 Redis，我们假设不需要带宽限制。
	}
	// --- 带宽管理器初始化完毕 ---

	// 注意：createPHPHandler 不再需要 manager 参数
	phpHandler := createPHPHandler(
		logger,
		connFactory,
		config.DocRoot,
		config.AccelRoot,
		config.MainPHPFile,
		// 移除 tokenManager
		config.TrustedProxies,
	)

	server := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      phpHandler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	logger.Info("服务器启动中...")
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		logger.Error("无法在指定地址监听", "address", config.ListenAddr, "error", err)
		os.Exit(1) // 替换 log.Fatalf
	}

	logger.Info("服务器已优雅停止")
}
