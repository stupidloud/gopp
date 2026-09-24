package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// 示例 config.yaml 除有意不同的项外，应与代码中的默认值一致
func TestExampleConfigMatchesDefaults(t *testing.T) {
	got, err := loadConfig("config.yaml", true)
	if err != nil {
		t.Fatal(err)
	}
	want := defaultConfig
	want.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	want.RedisBackend = true
	if err := want.prepare(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config.yaml 与默认值不一致：\n got  %+v\n want %+v", got, want)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none.yaml")
	if _, err := loadConfig(missing, false); err != nil {
		t.Errorf("未指定配置文件且默认文件不存在时应使用默认配置：%v", err)
	}
	if _, err := loadConfig(missing, true); err == nil {
		t.Error("显式指定的配置文件不存在时应报错")
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	for name, content := range map[string]string{
		"YAML 语法错误":          "listen_addr: [",
		"非法 trusted_proxies": "trusted_proxies: [not-an-ip]",
		"非法日志级别":             "log_level: loud",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.yaml")
			os.WriteFile(p, []byte(content), 0o644)
			if _, err := loadConfig(p, true); err == nil {
				t.Error("应报错")
			}
		})
	}
}
