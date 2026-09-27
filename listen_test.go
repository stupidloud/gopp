package main

import "testing"

func TestListenReusePort(t *testing.T) {
	a, err := listen("127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	addr := a.Addr().String()

	b, err := listen(addr, true)
	if err != nil {
		t.Fatalf("reuse_port 开启时应能再次监听同一端口：%v", err)
	}
	b.Close()

	if c, err := listen(addr, false); err == nil {
		c.Close()
		t.Error("未开启 reuse_port 时再次监听同一端口应失败")
	}
}
