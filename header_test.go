//go:build !frankenphp

package main

import (
	"net/http"
	"testing"

	"github.com/yookoala/gofast"
)

func TestMapHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.Header["Client-Ip"] = []string{"1.1.1.1"}
	r.Header["Client_ip"] = []string{"6.6.6.6"} // Go 规范化后的形式
	r.Header["X_forwarded_for"] = []string{"6.6.6.6"}
	r.Header["Proxy"] = []string{"http://evil:8080"}
	r.Header["Cookie"] = []string{"a=1", "b=2"}
	r.Header["Accept"] = []string{"text/html", "application/json"}
	r.Header["Content-Type"] = []string{"text/plain"}

	var params map[string]string
	inner := func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
		params = req.Params
		return nil, nil
	}
	req := gofast.NewRequest(r)
	mapHeader(inner)(nil, req)

	want := map[string]string{
		"HTTP_HOST":      "example.com",
		"HTTP_CLIENT_IP": "1.1.1.1",
		"HTTP_COOKIE":    "a=1; b=2",
		"HTTP_ACCEPT":    "text/html,application/json",
	}
	for k, v := range want {
		if params[k] != v {
			t.Errorf("%s = %q，期望 %q", k, params[k], v)
		}
	}
	for _, k := range []string{"HTTP_X_FORWARDED_FOR", "HTTP_PROXY", "HTTP_CONTENT_TYPE"} {
		if v, ok := params[k]; ok {
			t.Errorf("%s 不应设置，实际为 %q", k, v)
		}
	}
}
