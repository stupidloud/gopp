package main

import (
	"context"
	"fmt"
	"log/slog" // 替换 log
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

// (空行,移除旧注释)

// RateLimiterBackend 定义了令牌桶后端接口
type RateLimiterBackend interface {
	// GetLimiter 获取或创建指定令牌ID和速率的限速器
	GetLimiter(tokenID string, limit rate.Limit, burst int) (*RateLimiter, error)
	// Close 关闭后端连接
	Close() error
}

// TokenBucketManager 管理基于ID的令牌桶
type TokenBucketManager struct {
	backend RateLimiterBackend
	config  *Config
	logger  *slog.Logger // 添加 logger
}

// NewTokenBucketManager 创建一个新的TokenBucketManager,使用指定的后端.
func NewTokenBucketManager(config *Config, backend RateLimiterBackend, logger *slog.Logger) (*TokenBucketManager, error) { // 添加 logger 参数
	// (移除旧的实现注释)
	if backend == nil {
		return nil, fmt.Errorf("NewTokenBucketManager 需要一个非空的 RateLimiterBackend") // 确保 backend 不为 nil
	}
	logger.Debug("TokenBucketManager 使用传入的后端", "backend_type", fmt.Sprintf("%T", backend))

	return &TokenBucketManager{
		backend: backend,
		config:  config,
		logger:  logger, // 存储 logger
	}, nil
}

// GetLimiter 获取或创建一个指定令牌ID和速率的RateLimiter
func (m *TokenBucketManager) GetLimiter(tokenID string, limit rate.Limit, burst int) *RateLimiter {
	limiter, err := m.backend.GetLimiter(tokenID, limit, burst)
	if err != nil {
		m.logger.Warn("获取后端限速器失败，使用无限速器", "token_id", tokenID, "error", err) // 使用 manager 的 logger
		// 创建无限速器时也需要传递 logger
		return NewRateLimiter(rate.Inf, burst, m.logger)
	}
	return limiter
}

// Close 关闭TokenBucketManager及其后端
func (m *TokenBucketManager) Close() error {
	if m.backend != nil {
		return m.backend.Close()
	}
	return nil
}

// MemoryBackend 使用内存存储实现RateLimiterBackend接口
type MemoryBackend struct {
	limiters map[string]*RateLimiter
	mu       sync.Mutex
	logger   *slog.Logger // 添加 logger
}

// NewMemoryBackend 创建一个新的内存后端
func NewMemoryBackend(logger *slog.Logger) *MemoryBackend { // 添加 logger 参数
	return &MemoryBackend{
		limiters: make(map[string]*RateLimiter),
		logger:   logger, // 存储 logger
	}
}

// GetLimiter 从内存中获取或创建一个限速器
func (b *MemoryBackend) GetLimiter(tokenID string, limit rate.Limit, burst int) (*RateLimiter, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Debug("内存后端: 尝试获取限速器", "token_id", tokenID)

	limiter, exists := b.limiters[tokenID]
	if !exists {
		// 创建新限速器时传递 logger
		limiter = NewRateLimiter(limit, burst, b.logger)
		b.logger.Debug("内存后端: 创建新限速器", "token_id", tokenID)

		b.limiters[tokenID] = limiter
	}
	return limiter, nil
}

// Close 关闭内存后端（无操作）
func (b *MemoryBackend) Close() error {
	return nil
}

// RedisBackend 使用Redis存储实现RateLimiterBackend接口
type RedisBackend struct {
	client     *redis.Client // Redis 客户端实例
	keyPrefix  string
	keyTTL     time.Duration
	localCache map[string]*RateLimiter // 本地缓存 RateLimiter 实例
	mu         sync.Mutex
	logger     *slog.Logger // 添加 logger
	ownsClient bool         // 标记是否由此后端创建和管理客户端连接
}

// NewRedisBackend 创建一个新的Redis后端.
// 可以选择传入一个现有的 redis.Client,或者传入 Redis 配置让后端自己创建.
func NewRedisBackend(cfg *Config, existingClient *redis.Client, logger *slog.Logger) (*RedisBackend, error) { // 添加 logger 参数
	var client *redis.Client
	ownsClient := false

	if existingClient != nil {
		client = existingClient
		logger.Debug("RedisBackend: 使用外部传入的 Redis 客户端")
	} else if cfg.RedisBackend {
		logger.Debug("RedisBackend: 根据配置创建新的 Redis 客户端")
		client = redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		})
		ownsClient = true // 标记此后端拥有客户端,需要在 Close 时关闭

		// 测试连接
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err != nil {
			// 如果创建并测试连接失败,关闭可能已部分初始化的客户端
			if ownsClient {
				client.Close()
			}
			return nil, fmt.Errorf("无法连接到 Redis: %w", err)
		}
		logger.Info("RedisBackend: 成功连接到 Redis", "address", cfg.RedisAddr)
	} else {
		return nil, fmt.Errorf("RedisBackend 需要 Redis 配置或一个现有的客户端")
	}

	return &RedisBackend{
		client:     client,
		keyPrefix:  cfg.RedisKeyPrefix,
		keyTTL:     time.Duration(cfg.RedisKeyTTL) * time.Second,
		localCache: make(map[string]*RateLimiter),
		ownsClient: ownsClient,
		logger:     logger, // 存储 logger
	}, nil
}

// getRedisKey 生成Redis键
func (b *RedisBackend) getRedisKey(tokenID string) string {
	return fmt.Sprintf("%s%s", b.keyPrefix, tokenID)
}

// GetLimiter 从Redis获取或创建一个限速器
func (b *RedisBackend) GetLimiter(tokenID string, limit rate.Limit, burst int) (*RateLimiter, error) {
	// 检查此后端的 Redis 客户端
	if b.client == nil {
		return nil, fmt.Errorf("RedisBackend 的 Redis 客户端未初始化")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// 优先检查本地缓存
	b.logger.Debug("Redis后端: 尝试从本地缓存获取限速器", "token_id", tokenID)

	if limiter, exists := b.localCache[tokenID]; exists {
		return limiter, nil
	}

	// 创建一个Redis限速器包装器
	// 注意:我们创建了自定义的RateLimiter实例,使用RedisRateWaiter作为waiter实现
	redisWaiter := &RedisRateWaiter{
		backend: b,
		tokenID: tokenID,
		limit:   limit,
		burst:   burst,
		limiter: rate.NewLimiter(limit, burst), // 本地后备限速器
		logger:  b.logger,                      // 传递 logger
	}

	// 创建使用Redis后端的限速器
	limiter := &RateLimiter{
		limiter: rate.NewLimiter(limit, burst), // 基本属性使用标准限速器
		waiter:  redisWaiter,                   // 但Wait操作使用Redis实现
		logger:  b.logger,                      // 传递 logger
	}

	// 缓存到本地
	b.logger.Debug("Redis后端: 将限速器缓存到本地", "token_id", tokenID)

	b.localCache[tokenID] = limiter

	return limiter, nil
}

// Close 关闭Redis后端.如果客户端是由此后端创建的,则关闭连接.
func (b *RedisBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ownsClient && b.client != nil {
		b.logger.Info("RedisBackend: 关闭拥有的 Redis 客户端")
		err := b.client.Close()
		b.client = nil // 清除引用
		return err
	} else if !b.ownsClient && b.client != nil {
		b.logger.Debug("RedisBackend: 不关闭外部传入的 Redis 客户端")
	}
	return nil
}

// RateWaiter 定义了Wait操作的接口
type RateWaiter interface {
	Wait(ctx context.Context, n int) error
}

// RateLimiter 是rate.Limiter的通用接口
type RateLimiter struct {
	limiter *rate.Limiter
	waiter  RateWaiter   // 可选的自定义Waiter实现
	logger  *slog.Logger // 添加 logger
}

// NewRateLimiter 使用给定的速率和突发值创建一个新的RateLimiter
func NewRateLimiter(r rate.Limit, b int, logger *slog.Logger) *RateLimiter { // 添加 logger 参数
	rl := &RateLimiter{
		limiter: rate.NewLimiter(r, b),
		logger:  logger, // 存储 logger
	}
	// 默认情况下,waiter 是 nil,所以会使用原生limiter实现 (Wait 方法会处理)
	return rl
}

// Wait 等待直到令牌可用或上下文被取消
func (rl *RateLimiter) Wait(ctx context.Context, n int) error {
	if rl.waiter != nil { // 使用自定义 waiter (如果存在)
		return rl.waiter.Wait(ctx, n)
	}
	// 如果没有自定义 waiter，使用标准 limiter 并记录日志
	rl.logger.Debug("标准限流器: 等待令牌", "requested_tokens", n)
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
	rl.limiter.SetLimit(newLimit) // 更新本地后备限速器
	// 尝试更新 waiter (如果它是 RedisRateWaiter)
	if redisWaiter, ok := rl.waiter.(*RedisRateWaiter); ok {
		redisWaiter.SetLimit(newLimit)
	}
}

// SetBurst 设置突发值大小
func (rl *RateLimiter) SetBurst(newBurst int) {
	rl.limiter.SetBurst(newBurst) // 更新本地后备限速器
	// 尝试更新 waiter (如果它是 RedisRateWaiter)
	if redisWaiter, ok := rl.waiter.(*RedisRateWaiter); ok {
		redisWaiter.SetBurst(newBurst)
	}
}

// RedisRateWaiter 是Redis实现的RateWaiter
type RedisRateWaiter struct {
	backend *RedisBackend
	tokenID string
	limit   rate.Limit
	burst   int
	limiter *rate.Limiter // 本地limiter用于紧急情况
	logger  *slog.Logger  // 添加 logger
}

// Wait 在Redis中等待直到令牌可用或上下文被取消
func (rl *RedisRateWaiter) Wait(ctx context.Context, n int) error {
	// 检查是否为无限速率
	if rl.limit == rate.Inf {
		rl.logger.Debug("Redis限流器: 无限速率，直接放行", "token_id", rl.tokenID) // 无限速率,无需等待
		return nil
	}

	// 检查Redis客户端是否已初始化
	if rl.backend.client == nil { // 检查 Redis 客户端是否可用
		rl.logger.Warn("Redis限流器: Redis 客户端不可用，使用本地限速器作为备份", "token_id", rl.tokenID)
		return rl.limiter.WaitN(ctx, n) // Redis 不可用,使用本地备份
	}
	// Redis限流算法实现
	// 使用Redis的令牌桶算法实现（lua脚本）
	script := redis.NewScript(`
local key = KEYS[1]
local tokens_requested = tonumber(ARGV[1])
-- rate表示每秒产生的令牌数量（tokens/second）,用于根据经过的时间计算新增的令牌数
local rate = tonumber(ARGV[2])
local capacity = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

-- 获取当前桶状态,如果不存在则创建
local bucket = redis.call('hmget', key, 'tokens', 'last_update')
local tokens
local last_update

if bucket[1] == false then
-- 新建桶,填满令牌
tokens = capacity
last_update = now
else
tokens = tonumber(bucket[1])
last_update = tonumber(bucket[2])

-- 计算从上次更新到现在应该添加多少令牌
local elapsed = math.max(0, now - last_update)
-- 将elapsed从纳秒转换为秒
local elapsed_seconds = elapsed / 1000000000
-- 计算生成的令牌数量,使用秒为单位直接计算
local tokens_added = elapsed_seconds * rate
-- 确保不超过容量
local new_tokens = math.min(capacity, tokens + tokens_added)
tokens = new_tokens
end

-- 检查是否有足够的令牌
local allowed = 0
local wait_time = 0
local tokens_to_save -- 用于存储最终要保存回 Redis 的令牌数

-- 注意：这里的 'tokens' 变量是在脚本前面计算好的、包含了新补充令牌的当前桶内令牌数
if tokens >= tokens_requested then
  -- 有足够的令牌,允许请求
  allowed = 1
  wait_time = 0
  tokens_to_save = tokens - tokens_requested -- 扣除请求的令牌
else
  -- 令牌不足,计算等待时间
  allowed = 0
  local needed_tokens = tokens_requested - tokens -- 计算还差多少令牌
  wait_time = math.ceil(needed_tokens * 1000000000 / rate) -- 计算需要等待多久才能补足差额
  -- 保存反映“欠账”的令牌数（当前令牌减去请求的令牌，结果为负数或零）
  -- 这表示为了满足这个被延迟的请求，我们已经预支了未来的令牌
  tokens_to_save = tokens - tokens_requested
end

-- 更新桶状态，保存计算后的令牌数和当前时间戳
redis.call('hmset', key, 'tokens', tokens_to_save, 'last_update', now)
redis.call('expire', key, ttl) -- 设置TTL

return {allowed, wait_time}
`)

	// 转换速率限制（tokens/second）为浮点数
	ratePerSecond := float64(rl.limit)
	// 使用 backend 内部的 client
	rl.logger.Debug("Redis限流器: 调用 Lua 脚本",
		"token_id", rl.tokenID,
		"requested_tokens", n,
		"rate_per_second", ratePerSecond,
		"burst", rl.burst,
		"ttl_seconds", int(rl.backend.keyTTL.Seconds()))
	result, err := script.Run(ctx, rl.backend.client,
		[]string{rl.backend.getRedisKey(rl.tokenID)},
		n, // 请求的令牌数
		ratePerSecond,
		rl.burst,
		time.Now().UnixNano(),
		int(rl.backend.keyTTL.Seconds()),
	).Result()

	// 添加日志记录脚本执行后的原始结果
	rl.logger.Debug("Redis限流器: Lua 脚本原始返回", "token_id", rl.tokenID, "result", result, "error", err)
	if err != nil {
		rl.logger.Error("Redis限流器: 执行 Redis 脚本出错，使用本地限速器作为后备", "token_id", rl.tokenID, "error", err)
		return rl.limiter.WaitN(ctx, n)
	}

	// 解析结果
	results, ok := result.([]interface{})
	if !ok || len(results) != 2 {
		return fmt.Errorf("意外的Redis脚本返回结果")
	}

	allowed, ok := results[0].(int64)
	// [移除之前错误插入且位置错误的日志]
	if !ok {
		return fmt.Errorf("无法解析Redis脚本返回的allowed值")
	}

	// 处理allowed非0或1的异常情况
	if allowed != 0 && allowed != 1 {
		return fmt.Errorf("意外的allowed值: %d", allowed)
	} else if allowed == 1 {
		rl.logger.Debug("Redis限流器: 有足够令牌，立即通过", "token_id", rl.tokenID, "requested_tokens", n) // 允许立即通过
		return nil
	}

	waitTime, ok := results[1].(int64)
	if !ok {
		return fmt.Errorf("无法解析Redis脚本返回的wait_time值")
	}
	// 添加日志记录解析后的结果
	rl.logger.Debug("Redis限流器: Lua 脚本解析后", "token_id", rl.tokenID, "allowed", allowed, "wait_time_ns", waitTime)
	waitDuration := time.Duration(waitTime) // waitTime 本身就是纳秒数,直接转换
	rl.logger.Debug("Redis限流器: 令牌不足，需要等待", "token_id", rl.tokenID, "requested_tokens", n, "wait_duration", waitDuration)
	timer := time.NewTimer(waitDuration)
	defer timer.Stop()

	select {
	case <-timer.C:
		rl.logger.Debug("Redis限流器: 等待完成，已放行", "token_id", rl.tokenID, "requested_tokens", n) // 等待时间结束
		return nil
	case <-ctx.Done():
		err := ctx.Err() // 上下文取消
		rl.logger.Warn("Redis限流器: 上下文取消", "token_id", rl.tokenID, "error", err)
		return err
	}
}

// Limit 返回速率限制
func (rl *RedisRateWaiter) Limit() rate.Limit {
	return rl.limit
}

// Burst 返回突发值大小
func (rl *RedisRateWaiter) Burst() int {
	return rl.burst
}

// SetLimit 设置速率限制
func (rl *RedisRateWaiter) SetLimit(newLimit rate.Limit) {
	rl.limit = newLimit
	rl.limiter.SetLimit(newLimit) // 同时更新本地限速器
}

// SetBurst 设置突发值大小
func (rl *RedisRateWaiter) SetBurst(newBurst int) {
	rl.burst = newBurst
	rl.limiter.SetBurst(newBurst) // 同时更新本地限速器
}
