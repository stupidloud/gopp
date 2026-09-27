package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// connTracker 通过 http.Server.ConnState 记录尚未关闭的连接
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[net.Conn]struct{})}
}

func (t *connTracker) hook(c net.Conn, state http.ConnState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch state {
	case http.StateNew:
		t.conns[c] = struct{}{}
	case http.StateClosed, http.StateHijacked:
		delete(t.conns, c)
	}
}

func (t *connTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// gracefulStop 停止接受新连接并等待已有连接全部结束，ctx 到期时返回其错误（由调用方强制关闭）。
//
// 不用 http.Server.Shutdown：它开始后，已 accept 但尚未读到请求的连接在读到请求时会被直接断开、
// 不返回响应（net/http conn.serve 中的 shuttingDown 检查），替换二进制时恰好在旧进程停止前建立的
// 连接就会失败。这里改为关闭 keep-alive：空闲连接立即关闭，其余连接处理完当前请求后关闭。
func gracefulStop(ctx context.Context, server *http.Server, ln net.Listener, tracker *connTracker) error {
	ln.Close()
	server.SetKeepAlivesEnabled(false)

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for tracker.count() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return nil
}
