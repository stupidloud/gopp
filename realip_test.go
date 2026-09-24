package main

import (
	"net/http"
	"testing"
)

func TestGetRealIP(t *testing.T) {
	cfg := Config{TrustedProxies: []string{"10.0.0.0/8", "192.168.1.1", "fd00::/8"}}
	if err := cfg.prepare(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, remote, xff, xRealIP, want string
	}{
		{"直连不可信，忽略转发头", "1.2.3.4:5000", "9.9.9.9", "8.8.8.8", "1.2.3.4"},
		{"可信代理，取 XFF 最右不可信地址", "10.0.0.1:5000", "6.6.6.6, 1.2.3.4", "", "1.2.3.4"},
		{"跳过链上的可信代理", "10.0.0.1:5000", "6.6.6.6, 1.2.3.4, 10.1.1.1, 192.168.1.1", "", "1.2.3.4"},
		{"伪造的最左地址不被采信", "10.0.0.1:5000", "127.0.0.1, 1.2.3.4", "", "1.2.3.4"},
		{"非法值停止，取最后确认的一跳", "10.0.0.1:5000", "1.2.3.4, garbage, 10.1.1.1", "", "10.1.1.1"},
		{"全部可信时取最左", "10.0.0.1:5000", "10.2.2.2, 10.1.1.1", "", "10.2.2.2"},
		{"无 XFF 时用 X-Real-IP", "10.0.0.1:5000", "", "5.6.7.8", "5.6.7.8"},
		{"非法 X-Real-IP 忽略", "10.0.0.1:5000", "", "not-an-ip", "10.0.0.1"},
		{"单个 IP 形式的可信代理", "192.168.1.1:5000", "1.2.3.4", "", "1.2.3.4"},
		{"IPv6 可信代理", "[fd00::1]:5000", "2001:db8::1", "", "2001:db8::1"},
		{"IPv4 映射地址", "[::ffff:10.0.0.1]:5000", "1.2.3.4", "", "1.2.3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if got := GetRealIP(r, cfg.trustedProxyNets); got != tt.want {
				t.Errorf("GetRealIP = %q，期望 %q", got, tt.want)
			}
		})
	}
}

func TestPrepareRejectsInvalidTrustedProxy(t *testing.T) {
	cfg := Config{TrustedProxies: []string{"10.0.0.0/33"}}
	if err := cfg.prepare(); err == nil {
		t.Error("非法 CIDR 应报错")
	}
}
