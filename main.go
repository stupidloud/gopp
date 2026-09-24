package main

import (
	"flag"
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

const (
	// 只限制读取请求头的时间，不限制请求体（上传）和响应（下载）的时长：
	// 慢客户端由前面的反向代理处理
	readHeaderTimeout = 10 * time.Second
	// 需长于反向代理到 gopp 的 keep-alive 空闲超时（nginx upstream 默认 60s），
	// 否则代理可能复用 gopp 刚关闭的连接而偶发 502
	idleTimeout = 120 * time.Second
)

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()
	configGiven := false
	flag.Visit(func(f *flag.Flag) { configGiven = configGiven || f.Name == "config" })

	var err error
	appCtx := &AppContext{}
	// 未指定 -config 且默认的 config.yaml 不存在时使用默认配置
	appCtx.Config, err = loadConfig(*configPath, configGiven)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败：%v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: appCtx.Config.LogLevel})
	appCtx.Logger = slog.New(logHandler)

	appCtx.Logger.Info("日志系统初始化完成", "level", appCtx.Config.LogLevel.String())

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
		Addr:              appCtx.Config.ListenAddr,
		Handler:           phpHandler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	appCtx.Logger.Info("服务器启动中...")
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		appCtx.Logger.Error("无法在指定地址监听", "address", appCtx.Config.ListenAddr, "error", err)
		os.Exit(1)
	}

	appCtx.Logger.Info("服务器已优雅停止")
}
