package main

import (
	"context"
	"sync" // Added sync import for Mutex

	"golang.org/x/time/rate"
	"time"
)

// TokenBucketManager 管理基于ID的令牌桶
type TokenBucketManager struct {
	limiters map[string]*RateLimiter
	mu       sync.Mutex
}

// NewTokenBucketManager 创建一个新的TokenBucketManager
func NewTokenBucketManager() *TokenBucketManager {
	return &TokenBucketManager{
		limiters: make(map[string]*RateLimiter),
	}
}

// GetLimiter 获取或创建一个指定令牌ID和速率的RateLimiter
// 注意: 此基础版本不会更新现有限速器的速率
func (m *TokenBucketManager) GetLimiter(tokenID string, limit rate.Limit, burst int) *RateLimiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	limiter, exists := m.limiters[tokenID]
	if !exists {
		limiter = NewRateLimiter(limit, burst)
		m.limiters[tokenID] = limiter
		// 如果需要可以考虑在此添加日志
	}
	return limiter
}

// RateLimiter 是rate.Limiter的包装器，提供了Wait方法
type RateLimiter struct {
	limiter *rate.Limiter
}

// NewRateLimiter 使用给定的速率和突发值创建一个新的RateLimiter
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(r, b),
	}
}

// Wait 等待直到令牌可用或上下文被取消
func (rl *RateLimiter) Wait(ctx context.Context, n int) error {
	return rl.limiter.WaitN(ctx, n)
}

// Limit 返回速率限制
func (rl *RateLimiter) Limit() rate.Limit {
	return rl.limiter.Limit()
}

// Burst 返回突发值大小
func (rl *RateLimiter) Burst() int {
	return rl.limiter.Burst()
}

// SetLimit 设置速率限制
func (rl *RateLimiter) SetLimit(newLimit rate.Limit) {
	rl.limiter.SetLimit(newLimit)
}

// SetBurst 设置突发值大小
func (rl *RateLimiter) SetBurst(newBurst int) {
	rl.limiter.SetBurst(newBurst)
}

// AllowN 报告n个事件是否可以在当前时间发生
func (rl *RateLimiter) AllowN(now time.Time, n int) bool {
	return rl.limiter.AllowN(now, n)
}
