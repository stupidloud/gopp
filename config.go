package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

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
	SendTimeoutSeconds  int      `yaml:"send_timeout_seconds"`
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

	trustedProxyNets []netip.Prefix // 由 TrustedProxies 解析得到
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
	SendTimeoutSeconds:  60,
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

	if err := config.prepare(); err != nil {
		return config, fmt.Errorf("invalid config file %s: %w", path, err)
	}
	return config, nil
}

// prepare 校验配置并计算派生字段
func (c *Config) prepare() error {
	c.trustedProxyNets = c.trustedProxyNets[:0:0]
	for _, s := range c.TrustedProxies {
		p, err := parseIPOrCIDR(s)
		if err != nil {
			return fmt.Errorf("trusted_proxies: %w", err)
		}
		c.trustedProxyNets = append(c.trustedProxyNets, p)
	}
	return nil
}

// parseIPOrCIDR 解析 "10.0.0.0/8" 或单个 IP（视为 /32 或 /128）
func parseIPOrCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}
