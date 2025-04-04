package main

import (
	"fmt"
	"os"

	"log/slog"

	"gopkg.in/yaml.v3"
)

// 定义日志级别常量
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type Config struct {
	ListenAddr          string   `yaml:"listen_addr"`
	FPMNetwork          string   `yaml:"fpm_network"`
	FPMAddress          string   `yaml:"fpm_address"`
	DocRoot             string   `yaml:"doc_root"`
	AccelRoot           string   `yaml:"accel_root"`
	ReadTimeoutSeconds  int      `yaml:"read_timeout_seconds"`
	WriteTimeoutSeconds int      `yaml:"write_timeout_seconds"`
	IdleTimeoutSeconds  int      `yaml:"idle_timeout_seconds"`
	MainPHPFile         string   `yaml:"main_php_file"`
	TrustedProxies      []string `yaml:"trusted_proxies"`

	// Redis配置
	RedisBackend   bool   `yaml:"redis_backend"`
	RedisAddr      string `yaml:"redis_addr"`
	RedisPassword  string `yaml:"redis_password"`
	RedisDB        int    `yaml:"redis_db"`
	RedisKeyPrefix string `yaml:"redis_key_prefix"`
	RedisKeyTTL    int    `yaml:"redis_key_ttl"`

	LogLevel slog.Level `yaml:"log_level"`
}

var defaultConfig = Config{
	ListenAddr:          ":8082",
	FPMNetwork:          "tcp",
	FPMAddress:          "127.0.0.1:9000",
	DocRoot:             "/srv/gopp",
	AccelRoot:           "/srv/data",
	ReadTimeoutSeconds:  15,
	WriteTimeoutSeconds: 0,
	IdleTimeoutSeconds:  0,
	MainPHPFile:         "index.php",
	TrustedProxies:      []string{}, // 初始化为空切片而非nil

	// Redis默认配置
	RedisBackend:   false,
	RedisAddr:      "localhost:6379",
	RedisPassword:  "",
	RedisDB:        0,
	RedisKeyPrefix: "gopp:rate:",
	RedisKeyTTL:    3600,
	LogLevel:       LevelInfo, // 默认日志级别
}

func loadConfig(path string) (Config, error) {
	config := defaultConfig

	// 如果配置文件不存在，直接返回默认配置
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// 直接解析到config结构体
	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}

	// 处理特殊字段
	if config.MainPHPFile == "" {
		config.MainPHPFile = defaultConfig.MainPHPFile
	}

	return config, nil
}
