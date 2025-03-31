package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// 用于存储配置值的Config结构体
type Config struct {
	ListenAddr           string `yaml:"listen_addr"`
	FPMNetwork           string `yaml:"fpm_network"`
	FPMAddress           string `yaml:"fpm_address"`
	DocRoot              string `yaml:"doc_root"`
	AccelRoot            string `yaml:"accel_root"`
	ReadTimeoutSeconds   int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSeconds  int    `yaml:"write_timeout_seconds"`
	IdleTimeoutSeconds   int    `yaml:"idle_timeout_seconds"`
	MainPHPFile          string `yaml:"main_php_file"`
}

// 默认配置值
var defaultConfig = Config{
	ListenAddr:           ":8082",
	FPMNetwork:           "tcp",
	FPMAddress:           "127.0.0.1:9000",
	DocRoot:              "/srv/gopp",
	AccelRoot:            "/srv/data",
	ReadTimeoutSeconds:   15,
	WriteTimeoutSeconds:  0,
	IdleTimeoutSeconds:   0,
	MainPHPFile:          "index.php",
}

// loadConfig从YAML文件加载配置
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
		return config, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}
	// 确保MainPHPFile有默认值，以防配置文件中未设置
	if config.MainPHPFile == "" {
		config.MainPHPFile = defaultConfig.MainPHPFile
	}
	return config, nil
}
