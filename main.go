package main

import (
	"log"
	"net/http"
	"time"

	"github.com/yookoala/gofast"
	// Remove unused imports like context, fmt, io, mime, net, path/filepath, strconv, strings, syscall, sync, rate, yaml
)

// Global config variable (consider passing it explicitly if preferred)
var config Config

func main() {
	var err error
	// Load configuration using the function from config.go
	config, err = loadConfig("config.yaml")
	if err != nil {
		// loadConfig now returns default config on file not found,
		// so this error is likely for parsing issues.
		log.Printf("Warning: Could not load or parse config.yaml: %v. Using default configuration.", err)
		// config already holds defaultConfig in case of error return from loadConfig
	}

	// Convert timeouts to time.Duration
	readTimeout := time.Duration(config.ReadTimeoutSeconds) * time.Second
	writeTimeout := time.Duration(config.WriteTimeoutSeconds) * time.Second
	idleTimeout := time.Duration(config.IdleTimeoutSeconds) * time.Second

	log.Printf("Starting HTTP proxy server on %s", config.ListenAddr)
	log.Printf("Backend PHP-FPM: %s %s", config.FPMNetwork, config.FPMAddress)
	log.Printf("Document Root: %s", config.DocRoot)
	log.Printf("X-Accel Root: %s", config.AccelRoot)
	log.Printf("Main PHP File: %s", config.MainPHPFile) // Log the main PHP file being used

	// 创建连接工厂
	connFactory := gofast.SimpleConnFactory(config.FPMNetwork, config.FPMAddress)

	// 创建令牌桶管理器 (from ratelimit.go)
	tokenManager := NewTokenBucketManager()

	// 创建处理器 (from handler.go)
	// Pass config values and token manager explicitly
	phpHandler := createPHPHandler(
		connFactory,
		config.DocRoot,
		config.AccelRoot,
		config.MainPHPFile, // Pass main PHP file from config
		tokenManager,       // Pass the token manager instance
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
	log.Printf("Server starting...")
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", config.ListenAddr, err)
	}

	log.Println("Server stopped gracefully")
}

// Removed Config struct, defaultConfig, loadConfig (moved to config.go)
// Removed TokenBucketManager (moved to ratelimit.go)
// Removed createPHPHandler, responseInterceptor, sendFileWithSendfile, etc. (moved to handler.go)
