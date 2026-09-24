package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"log/slog"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr     string   `yaml:"listen_addr"`
	FPMNetwork     string   `yaml:"fpm_network"`
	FPMAddress     string   `yaml:"fpm_address"`
	DocRoot        string   `yaml:"doc_root"`
	AccelRoot      string   `yaml:"accel_root"`
	MainPHPFile    string   `yaml:"main_php_file"`
	TrustedProxies []string `yaml:"trusted_proxies"`

	// 以下仅用于内嵌 PHP 的构建（-tags frankenphp）
	PHPThreads    int    `yaml:"php_threads"`     // PHP 线程数，0 为 CPU 数的 2 倍
	PHPWorkerFile string `yaml:"php_worker_file"` // worker 模式入口脚本（相对 doc_root），为空不启用
	PHPWorkerNum  int    `yaml:"php_worker_num"`  // worker 线程数，0 为 CPU 数的 2 倍

	// Redis配置
	RedisBackend   bool   `yaml:"redis_backend"`
	RedisAddr      string `yaml:"redis_addr"`
	RedisPassword  string `yaml:"redis_password"`
	RedisDB        int    `yaml:"redis_db"`
	RedisKeyPrefix string `yaml:"redis_key_prefix"`

	LogLevel slog.Level `yaml:"log_level"`

	trustedProxyNets []netip.Prefix // 由 TrustedProxies 解析得到
}

var defaultConfig = Config{
	ListenAddr:     ":8082",
	FPMNetwork:     "tcp",
	FPMAddress:     "127.0.0.1:9000",
	DocRoot:        "/srv/gopp",
	AccelRoot:      "/srv/protected_files",
	MainPHPFile:    "index.php",
	TrustedProxies: []string{}, // 初始化为空切片而非nil

	// Redis默认配置
	RedisBackend:   false,
	RedisAddr:      "localhost:6379",
	RedisPassword:  "",
	RedisDB:        0,
	RedisKeyPrefix: "gopp:rate:",
	LogLevel:       slog.LevelInfo,
}

// loadConfig 加载配置文件；required 为 false 时文件不存在则使用默认配置
func loadConfig(path string, required bool) (Config, error) {
	config := defaultConfig

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return config, config.prepare()
		}
		return config, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}

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
	// SCRIPT_FILENAME 需要绝对路径
	for _, dir := range []*string{&c.DocRoot, &c.AccelRoot} {
		abs, err := filepath.Abs(*dir)
		if err != nil {
			return err
		}
		*dir = abs
	}

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
