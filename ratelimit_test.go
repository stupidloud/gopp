package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// testRedisConfig 返回指向测试 Redis 的配置（地址取 GOPP_TEST_REDIS，默认 127.0.0.1:6379），
// Redis 不可达时跳过测试。每个测试使用独立的 key 前缀。
func testRedisConfig(t *testing.T) Config {
	t.Helper()
	addr := os.Getenv("GOPP_TEST_REDIS")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis %s 不可用，跳过: %v", addr, err)
	}
	cfg := defaultConfig
	cfg.RedisBackend = true
	cfg.RedisAddr = addr
	cfg.RedisKeyPrefix = fmt.Sprintf("gopp:test:%d:", time.Now().UnixNano())
	return cfg
}

// measure 返回 f 的耗时
func measure(t *testing.T, f func() error) time.Duration {
	t.Helper()
	start := time.Now()
	if err := f(); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

func assertDuration(t *testing.T, got, want time.Duration) {
	t.Helper()
	if got < want-150*time.Millisecond || got > want+400*time.Millisecond {
		t.Errorf("耗时 %v，期望约 %v", got, want)
	}
}

func TestLocalLimiterRate(t *testing.T) {
	m := NewLimiterManager(defaultConfig, discardLogger)
	const rate = 200 << 10
	l := m.Get("user", rate)
	// 桶初始满（1 秒的量），之后按速率补充：(500K-200K)/200K = 1.5s
	d := measure(t, func() error {
		for i := 0; i < 5; i++ {
			if err := l.WaitN(context.Background(), 100<<10); err != nil {
				return err
			}
		}
		return nil
	})
	assertDuration(t, d, 1500*time.Millisecond)
}

func TestLocalLimiterSharedByToken(t *testing.T) {
	m := NewLimiterManager(defaultConfig, discardLogger)
	if m.Get("a", 1000) != m.Get("a", 1000) {
		t.Error("同一 token 应共享限速器")
	}
	if m.Get("a", 1000) == m.Get("b", 1000) {
		t.Error("不同 token 不应共享限速器")
	}
	if m.Get("", 1000) == m.Get("", 1000) {
		t.Error("未指定 token 时每个连接应独立限速")
	}
	if m.Get("a", 0) != nil {
		t.Error("速率为 0 时应不限速")
	}
}

// 请求量大于桶容量（速率低于块大小）时不应报错，而是分段等待
func TestLocalLimiterRequestLargerThanBurst(t *testing.T) {
	m := NewLimiterManager(defaultConfig, discardLogger)
	l := m.Get("", 100<<10)
	d := measure(t, func() error { return l.WaitN(context.Background(), 256<<10) })
	assertDuration(t, d, 1560*time.Millisecond) // (256K-100K)/100K
}

func TestLimiterContextCancel(t *testing.T) {
	m := NewLimiterManager(defaultConfig, discardLogger)
	l := m.Get("", 1000)
	_ = l.WaitN(context.Background(), 1000) // 耗尽桶
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.WaitN(ctx, 1000); err == nil {
		t.Error("ctx 取消后应返回错误")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("ctx 取消后应立即返回")
	}
}

// 两个实例（两个 LimiterManager）共享同一 token 时，总速率受 Redis 全局令牌桶限制
func TestRedisLimiterGlobalAcrossInstances(t *testing.T) {
	cfg := testRedisConfig(t)
	m1 := NewLimiterManager(cfg, discardLogger)
	m2 := NewLimiterManager(cfg, discardLogger)
	defer m1.Close()
	defer m2.Close()

	const rate = 200 << 10
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	start := time.Now()
	// 每个实例两个连接，每个连接 125K，共 500K：(500K-200K)/200K = 1.5s
	for _, m := range []*LimiterManager{m1, m2} {
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				l := m.Get("user", rate)
				for sent := 0; sent < 125<<10; sent += 25 << 10 {
					if err := l.WaitN(context.Background(), 25<<10); err != nil {
						errs <- err
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	assertDuration(t, time.Since(start), 1500*time.Millisecond)
	if m1.redisDown.Load() || m2.redisDown.Load() {
		t.Error("Redis 正常时不应退回本地限速")
	}
}

func TestRedisLimiterRequestLargerThanBurst(t *testing.T) {
	cfg := testRedisConfig(t)
	m := NewLimiterManager(cfg, discardLogger)
	defer m.Close()
	l := m.Get("user", 100<<10)
	d := measure(t, func() error { return l.WaitN(context.Background(), 256<<10) })
	assertDuration(t, d, 1560*time.Millisecond)
}

// Redis 不可用时退回本地限速：不报错、不放开
func TestRedisLimiterFallbackWhenDown(t *testing.T) {
	cfg := defaultConfig
	cfg.RedisBackend = true
	cfg.RedisAddr = "127.0.0.1:1" // 无服务监听
	m := NewLimiterManager(cfg, discardLogger)
	defer m.Close()
	if !m.redisDown.Load() {
		t.Fatal("Ping 失败后应标记 Redis 不可用")
	}
	l := m.Get("user", 200<<10)
	d := measure(t, func() error { return l.WaitN(context.Background(), 500<<10) })
	assertDuration(t, d, 1500*time.Millisecond)
}
