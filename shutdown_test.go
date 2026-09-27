package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func startTestServer(t *testing.T, handler http.HandlerFunc) (*http.Server, net.Listener, *connTracker) {
	t.Helper()
	ln, err := listen("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	tracker := newConnTracker()
	server := &http.Server{Handler: handler, ConnState: tracker.hook}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })
	return server, ln, tracker
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("等待超时")
		}
	}
}

// 已 accept 但请求尚未到达的连接，在停止过程中发来的请求仍应得到正常响应
func TestGracefulStopServesAcceptedConn(t *testing.T) {
	server, ln, tracker := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, func() bool { return tracker.count() == 1 })

	done := make(chan error, 1)
	go func() { done <- gracefulStop(context.Background(), server, ln, tracker) }()
	time.Sleep(100 * time.Millisecond) // 确保已进入停止流程

	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Error("停止后不应再接受新连接")
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("停止过程中已 accept 的连接未得到响应：%v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" || !resp.Close {
		t.Errorf("状态 %d，响应 %q，Connection: close = %v", resp.StatusCode, body, resp.Close)
	}
	if err := <-done; err != nil {
		t.Errorf("gracefulStop: %v", err)
	}
}

// 进行中的请求完成后才返回；超时返回 ctx 错误
func TestGracefulStopWaitsAndTimesOut(t *testing.T) {
	release := make(chan struct{})
	server, ln, tracker := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		io.WriteString(w, "done")
	})
	respCh := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			respCh <- err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		respCh <- string(b)
	}()
	waitFor(t, func() bool { return tracker.count() == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := gracefulStop(ctx, server, ln, tracker); err == nil {
		t.Error("请求未完成时应超时")
	}

	close(release)
	if got := <-respCh; got != "done" {
		t.Errorf("进行中的请求应正常完成：%q", got)
	}
	if err := gracefulStop(context.Background(), server, ln, tracker); err != nil {
		t.Errorf("请求完成后应正常返回：%v", err)
	}
}
