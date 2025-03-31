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

// NewTokenBucketManager creates a new TokenBucketManager.
func NewTokenBucketManager() *TokenBucketManager {
	return &TokenBucketManager{
		limiters: make(map[string]*RateLimiter),
	}
}

// GetLimiter retrieves or creates a RateLimiter for a given token ID and rate.
// Note: This basic version doesn't update existing limiter rates.
func (m *TokenBucketManager) GetLimiter(tokenID string, limit rate.Limit, burst int) *RateLimiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	limiter, exists := m.limiters[tokenID]
	if !exists {
		limiter = NewRateLimiter(limit, burst)
		m.limiters[tokenID] = limiter
		// Consider adding logging here if needed
	}
	return limiter
}

// RateLimiter is a wrapper around rate.Limiter that provides a Wait method.
type RateLimiter struct {
	limiter *rate.Limiter
}

// NewRateLimiter creates a new RateLimiter with the given rate and burst.
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(r, b),
	}
}

// Wait waits until a token is available or the context is cancelled.
func (rl *RateLimiter) Wait(ctx context.Context, n int) error {
	return rl.limiter.WaitN(ctx, n)
}

// Limit returns the rate limit.
func (rl *RateLimiter) Limit() rate.Limit {
	return rl.limiter.Limit()
}

// Burst returns the burst size.
func (rl *RateLimiter) Burst() int {
	return rl.limiter.Burst()
}

// SetLimit sets the rate limit.
func (rl *RateLimiter) SetLimit(newLimit rate.Limit) {
	rl.limiter.SetLimit(newLimit)
}

// SetBurst sets the burst size.
func (rl *RateLimiter) SetBurst(newBurst int) {
	rl.limiter.SetBurst(newBurst)
}

// AllowN reports whether n events may happen at time now.
func (rl *RateLimiter) AllowN(now time.Time, n int) bool {
	return rl.limiter.AllowN(now, n)
}
