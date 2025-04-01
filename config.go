package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
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

	LogLevel string `yaml:"log_level"`
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

	// Redis默认配置
	RedisBackend:   false,
	RedisAddr:      "localhost:6379",
	RedisPassword:  "",
	RedisDB:        0,
	RedisKeyPrefix: "gopp:rate:",
	RedisKeyTTL:    3600,
}

func loadConfig(path string) (Config, error) {
	config := defaultConfig
	data, err := os.ReadFile(path)
	if err != nil {
		// 如果文件不存在，无错误地返回默认配置
		if os.IsNotExist(err) {
			return config, nil
		}
		return config, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		// 如果日志级别未设置，默认设为info
		if config.LogLevel == "" {
			config.LogLevel = "info"
		}
		return config, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}
	// 确保MainPHPFile有默认值，以防配置文件中未设置
	if config.MainPHPFile == "" {
		config.MainPHPFile = defaultConfig.MainPHPFile
	}
	// 处理trusted_proxies字段，若未设置则为空切片
	if config.TrustedProxies == nil {
		config.TrustedProxies = []string{}
	}
	return config, nil
}
