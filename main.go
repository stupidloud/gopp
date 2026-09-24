package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/yookoala/gofast"
)

// AppContext 包含应用程序运行所需的共享依赖项
type AppContext struct {
	Config      Config
	Logger      *slog.Logger
	ConnFactory gofast.ConnFactory
	Limiters    *LimiterManager
}

func main() {
	var err error
	appCtx := &AppContext{}
	appCtx.Config, err = loadConfig("config.yaml")
	if err != nil {
		// 如果加载或解析 config.yaml 失败，记录警告并使用默认配置
		fmt.Fprintf(os.Stderr, "警告：无法加载或解析 config.yaml：%v。使用默认配置。\n", err)
	}

	// 初始化日志
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: appCtx.Config.LogLevel})
	appCtx.Logger = slog.New(logHandler)

	appCtx.Logger.Info("日志系统初始化完成", "level", appCtx.Config.LogLevel.String())

	readTimeout := time.Duration(appCtx.Config.ReadTimeoutSeconds) * time.Second
	writeTimeout := time.Duration(appCtx.Config.WriteTimeoutSeconds) * time.Second
	idleTimeout := time.Duration(appCtx.Config.IdleTimeoutSeconds) * time.Second

	appCtx.Logger.Info("启动 HTTP 代理服务器", "address", appCtx.Config.ListenAddr)
	appCtx.Logger.Info("后端 PHP-FPM", "network", appCtx.Config.FPMNetwork, "address", appCtx.Config.FPMAddress)
	appCtx.Logger.Info("文档根目录", "path", appCtx.Config.DocRoot)
	appCtx.Logger.Info("X-Accel 根目录", "path", appCtx.Config.AccelRoot)
	appCtx.Logger.Info("主 PHP 文件", "file", appCtx.Config.MainPHPFile)

	appCtx.ConnFactory = gofast.SimpleConnFactory(appCtx.Config.FPMNetwork, appCtx.Config.FPMAddress)

	appCtx.Limiters = NewLimiterManager(appCtx.Config, appCtx.Logger)
	defer appCtx.Limiters.Close()

	phpHandler := createPHPHandler(appCtx)

	server := &http.Server{
		Addr:         appCtx.Config.ListenAddr,
		Handler:      phpHandler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	appCtx.Logger.Info("服务器启动中...")
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		appCtx.Logger.Error("无法在指定地址监听", "address", appCtx.Config.ListenAddr, "error", err)
		os.Exit(1)
	}

	appCtx.Logger.Info("服务器已优雅停止")
}
