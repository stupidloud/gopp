package main

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

const (
	limiterCacheSize = 10000
	// Redis 出错后在这段时间内直接走本地限速，避免每个块都去撞故障的 Redis
	redisRetryInterval = 5 * time.Second
)

// Limiter 限制传输速率：WaitN 阻塞直到允许再发送 n 字节，ctx 取消时立即返回
type Limiter interface {
	WaitN(ctx context.Context, n int) error
}

// tokenBucketScript 是 Redis 中的全局令牌桶（毫秒精度，时间取自 Redis TIME 以避免各实例时钟偏差）。
// KEYS[1] = 桶 key；ARGV = rate(字节/秒), burst(字节), want(字节)。
// 返回 0 表示领取成功；否则为需等待的毫秒数，等待后重试。
// 在写操作前调用 TIME（非确定性命令），要求 Redis >= 5（默认按效果复制）。
var tokenBucketScript = redis.NewScript(`
local rate, burst, want = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local s = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(s[1]) or burst
local ts = tonumber(s[2]) or now
tokens = math.min(burst, tokens + math.max(0, now - ts) * rate / 1000)
local wait = 0
if tokens >= want then
  tokens = tokens - want
else
  wait = math.ceil((want - tokens) * 1000 / rate)
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], math.ceil(burst * 1000 / rate) + 1000)
return wait
`)

// LimiterManager 按 token 管理限速器，同一 token 的所有连接共享速率。
//   - 未启用 Redis：每个 token 一个本地令牌桶，仅在本实例内共享
//   - 启用 Redis：全局令牌桶在 Redis 中，本地每个 token 一个额度池，
//     池空时向 Redis 领取一批额度；Redis 故障时退回本地限速
type LimiterManager struct {
	logger *slog.Logger
	local  *lru.Cache[string, *localLimiter]

	redis     *redis.Client // nil 表示不使用 Redis
	keyPrefix string
	pools     *lru.Cache[string, *quotaPool]

	redisDownUntil atomic.Int64 // UnixNano；在此之前不访问 Redis
	redisDown      atomic.Bool
}

func NewLimiterManager(cfg Config, logger *slog.Logger) *LimiterManager {
	m := &LimiterManager{logger: logger, keyPrefix: cfg.RedisKeyPrefix}
	m.local, _ = lru.New[string, *localLimiter](limiterCacheSize) // 仅在 size <= 0 时出错

	if !cfg.RedisBackend {
		logger.Info("带宽限制使用本地令牌桶（仅在本实例内共享）")
		return m
	}

	m.pools, _ = lru.New[string, *quotaPool](limiterCacheSize)
	m.redis = redis.NewClient(&redis.Options{
		Addr:         cfg.RedisAddr,
		Password:     cfg.RedisPassword,
		DB:           cfg.RedisDB,
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.redis.Ping(ctx).Err(); err != nil {
		// 不退出：Redis 恢复后自动切回全局限速
		m.markRedisDown(err)
	} else {
		logger.Info("带宽限制使用 Redis 全局令牌桶", "addr", cfg.RedisAddr)
	}
	return m
}

func (m *LimiterManager) Close() error {
	if m.redis != nil {
		return m.redis.Close()
	}
	return nil
}

// Get 返回速率为 bytesPerSec 的限速器；bytesPerSec <= 0 时返回 nil（不限速）。
// token 为空时只限制当前连接。
func (m *LimiterManager) Get(token string, bytesPerSec int) Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	if token == "" {
		return newLocalLimiter(bytesPerSec)
	}

	if m.redis == nil {
		l, ok := m.local.Get(token)
		if !ok {
			l = newLocalLimiter(bytesPerSec)
			if prev, found, _ := m.local.PeekOrAdd(token, l); found {
				l = prev // 并发创建时以先加入的为准
			}
		}
		l.setRate(bytesPerSec)
		return l
	}

	p, ok := m.pools.Get(token)
	if !ok {
		newP := &quotaPool{
			m:        m,
			key:      m.keyPrefix + token,
			sem:      make(chan struct{}, 1),
			fallback: newLocalLimiter(bytesPerSec),
		}
		newP.rate.Store(int64(bytesPerSec))
		p = newP
		if prev, found, _ := m.pools.PeekOrAdd(token, newP); found {
			p = prev
		}
	}
	p.setRate(bytesPerSec)
	return p
}

func (m *LimiterManager) redisAvailable() bool {
	return time.Now().UnixNano() >= m.redisDownUntil.Load()
}

func (m *LimiterManager) markRedisDown(err error) {
	m.redisDownUntil.Store(time.Now().Add(redisRetryInterval).UnixNano())
	if m.redisDown.CompareAndSwap(false, true) {
		m.logger.Error("Redis 不可用，带宽限制退回本地令牌桶（多实例时总速率可能超出限制）", "error", err)
	}
}

func (m *LimiterManager) markRedisUp() {
	if m.redisDown.CompareAndSwap(true, false) {
		m.logger.Info("Redis 已恢复，带宽限制切回全局令牌桶")
	}
}

// localLimiter 是本地令牌桶，桶容量为 1 秒的量
type localLimiter struct {
	lim *rate.Limiter
}

func newLocalLimiter(bytesPerSec int) *localLimiter {
	return &localLimiter{lim: rate.NewLimiter(rate.Limit(bytesPerSec), bytesPerSec)}
}

func (l *localLimiter) setRate(bytesPerSec int) {
	if l.lim.Limit() != rate.Limit(bytesPerSec) {
		l.lim.SetLimit(rate.Limit(bytesPerSec))
		l.lim.SetBurst(bytesPerSec)
	}
}

// WaitN 按不超过桶容量的片段等待，n 大于桶容量（如速率被调低）时不会报错
func (l *localLimiter) WaitN(ctx context.Context, n int) error {
	for n > 0 {
		k := min(n, l.lim.Burst())
		if err := l.lim.WaitN(ctx, k); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue // 等待期间桶容量被调低，按新容量重试
		}
		n -= k
	}
	return nil
}

// quotaPool 是本实例内某个 token 的额度池，该 token 在本实例的所有连接共用。
// 余额不足时向 Redis 全局令牌桶领取一批（速率的 1/10，即约 100ms 的量）。
type quotaPool struct {
	m        *LimiterManager
	key      string
	rate     atomic.Int64  // 字节/秒
	sem      chan struct{} // 同一时刻只有一个 goroutine 向 Redis 领取额度
	fallback *localLimiter // Redis 故障时使用

	mu      sync.Mutex
	balance int64
}

func (p *quotaPool) setRate(bytesPerSec int) {
	p.rate.Store(int64(bytesPerSec))
	p.fallback.setRate(bytesPerSec)
}

func (p *quotaPool) grantSize() int64 {
	return max(1, p.rate.Load()/10)
}

func (p *quotaPool) WaitN(ctx context.Context, n int) error {
	for remain := int64(n); remain > 0; {
		k := min(remain, p.grantSize())
		if err := p.take(ctx, k); err != nil {
			return err
		}
		remain -= k
	}
	return nil
}

func (p *quotaPool) tryTake(k int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.balance >= k {
		p.balance -= k
		return true
	}
	return false
}

func (p *quotaPool) take(ctx context.Context, k int64) error {
	for {
		if p.tryTake(k) {
			return nil
		}
		if !p.m.redisAvailable() {
			return p.fallback.WaitN(ctx, int(k))
		}

		select {
		case p.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		if p.tryTake(k) { // 等锁期间其他连接已领取
			<-p.sem
			return nil
		}
		err := p.refill(ctx)
		<-p.sem
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.m.markRedisDown(err)
			return p.fallback.WaitN(ctx, int(k))
		}
	}
}

// refill 向 Redis 全局令牌桶领取一批额度，令牌不足时按脚本返回的毫秒数等待后重试
func (p *quotaPool) refill(ctx context.Context) error {
	for {
		r := p.rate.Load()
		want := p.grantSize()
		wait, err := tokenBucketScript.Run(ctx, p.m.redis, []string{p.key}, r, r, want).Int64()
		if err != nil {
			return err
		}
		p.m.markRedisUp()
		if wait == 0 {
			p.mu.Lock()
			p.balance += want
			p.mu.Unlock()
			return nil
		}
		t := time.NewTimer(time.Duration(wait) * time.Millisecond)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}
