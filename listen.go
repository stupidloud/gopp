package main

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listen 监听 addr。reusePort 为 true 时设置 SO_REUSEPORT，允许新旧两个 gopp 同时监听同一端口，
// 用于不停服替换二进制：先启动新进程，再向旧进程发 SIGTERM，旧进程处理完进行中的请求后退出。
// 旧进程关闭监听时，已进入其队列但尚未 accept 的连接会被内核重置，
// 开启 sysctl net.ipv4.tcp_migrate_req=1（Linux 5.14+）后这些连接会转给新进程。
func listen(addr string, reusePort bool) (net.Listener, error) {
	var lc net.ListenConfig
	if reusePort {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return sockErr
		}
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
