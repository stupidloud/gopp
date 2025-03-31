package main

import (
	"log"
	"net/http"
	"time"

	"github.com/yookoala/gofast"
)

// 全局配置变量（如果愿意，可考虑显式传递）
var config Config

func main() {
	var err error
	// 使用 config.go 中的函数加载配置
	config, err = loadConfig("config.yaml")
	if err != nil {
// loadConfig 现在在文件未找到时返回默认配置，
// 因此此错误可能是解析问题导致的。
		log.Printf("警告：无法加载或解析 config.yaml：%v。使用默认配置。", err)
		// 当loadConfig返回错误时，config已经包含defaultConfig
	}

	// 将超时时间转换为 time.Duration
	readTimeout := time.Duration(config.ReadTimeoutSeconds) * time.Second
	writeTimeout := time.Duration(config.WriteTimeoutSeconds) * time.Second
	idleTimeout := time.Duration(config.IdleTimeoutSeconds) * time.Second

	log.Printf("在 %s 启动 HTTP 代理服务器", config.ListenAddr)
	log.Printf("后端 PHP-FPM：%s %s", config.FPMNetwork, config.FPMAddress)
	log.Printf("文档根目录：%s", config.DocRoot)
	log.Printf("X-Accel 根目录：%s", config.AccelRoot)
	log.Printf("主 PHP 文件：%s", config.MainPHPFile) // 记录正在使用的主 PHP 文件

	// 创建连接工厂
	connFactory := gofast.SimpleConnFactory(config.FPMNetwork, config.FPMAddress)

	// 创建令牌桶管理器（来自 ratelimit.go）
	tokenManager := NewTokenBucketManager()

// 创建处理器（来自 handler.go）
// 显式传递配置值和令牌桶管理器
	phpHandler := createPHPHandler(
		connFactory,
		config.DocRoot,
		config.AccelRoot,
		config.MainPHPFile, // 从配置传递主PHP文件
		tokenManager,       // 传递令牌管理器实例
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
	log.Printf("服务器启动中...")
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("无法在 %s 监听：%v\n", config.ListenAddr, err)
	}

	log.Println("服务器已优雅停止")
}
