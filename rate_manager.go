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
	logger  *slog.Logger
}

// NewTokenBucketManager 创建一个新的TokenBucketManager,使用指定的后端.
func NewTokenBucketManager(config *Config, backend RateLimiterBackend, logger *slog.Logger) (*TokenBucketManager, error) {
	if backend == nil {
		return nil, fmt.Errorf("NewTokenBucketManager 需要一个非空的 RateLimiterBackend")
	}
	logger.Debug("TokenBucketManager 使用传入的后端", "backend_type", fmt.Sprintf("%T", backend))

	return &TokenBucketManager{
		backend: backend,
		config:  config,
		logger:  logger,
	}, nil
}

// GetLimiter 获取或创建一个指定令牌ID和速率的RateLimiter
func (m *TokenBucketManager) GetLimiter(tokenID string, limit rate.Limit, burst int) *RateLimiter {
	limiter, err := m.backend.GetLimiter(tokenID, limit, burst)
	if err != nil {
		m.logger.Warn("获取后端限速器失败，使用无限速器", "token_id", tokenID, "error", err)
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
	logger   *slog.Logger
}

// NewMemoryBackend 创建一个新的内存后端
func NewMemoryBackend(logger *slog.Logger) *MemoryBackend {
	return &MemoryBackend{
		limiters: make(map[string]*RateLimiter),
		logger:   logger,
	}
}

// GetLimiter 从内存中获取或创建一个限速器
func (b *MemoryBackend) GetLimiter(tokenID string, limit rate.Limit, burst int) (*RateLimiter, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Debug("内存后端: 尝试获取限速器", "token_id", tokenID)

	limiter, exists := b.limiters[tokenID]
	if !exists {
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
	client     *redis.Client
	keyPrefix  string
	keyTTL     time.Duration
	localCache map[string]*RateLimiter
	mu         sync.Mutex
	logger     *slog.Logger
	ownsClient bool
}

// NewRedisBackend 创建一个新的Redis后端.
// 可以选择传入一个现有的 redis.Client,或者传入 Redis 配置让后端自己创建.
func NewRedisBackend(cfg *Config, existingClient *redis.Client, logger *slog.Logger) (*RedisBackend, error) {
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
		ownsClient = true

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err != nil {
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
		logger:     logger,
	}, nil
}

// getRedisKey 生成Redis键
func (b *RedisBackend) getRedisKey(tokenID string) string {
	return fmt.Sprintf("%s%s", b.keyPrefix, tokenID)
}

// GetLimiter 从Redis获取或创建一个限速器
func (b *RedisBackend) GetLimiter(tokenID string, limit rate.Limit, burst int) (*RateLimiter, error) {
	if b.client == nil {
		return nil, fmt.Errorf("RedisBackend 的 Redis 客户端未初始化")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Debug("Redis后端: 尝试从本地缓存获取限速器", "token_id", tokenID)

	if limiter, exists := b.localCache[tokenID]; exists {
		return limiter, nil
	}

	redisWaiter := &RedisRateWaiter{
		backend: b,
		tokenID: tokenID,
		limit:   limit,
		burst:   burst,
		limiter: rate.NewLimiter(limit, burst),
		logger:  b.logger,
	}

	limiter := &RateLimiter{
		limiter: rate.NewLimiter(limit, burst),
		waiter:  redisWaiter,
		logger:  b.logger,
	}

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
		b.client = nil
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
	waiter  RateWaiter
	logger  *slog.Logger
}

// NewRateLimiter 使用给定的速率和突发值创建一个新的RateLimiter
func NewRateLimiter(r rate.Limit, b int, logger *slog.Logger) *RateLimiter {
	rl := &RateLimiter{
		limiter: rate.NewLimiter(r, b),
		logger:  logger,
	}
	return rl
}

// Wait 等待直到令牌可用或上下文被取消
func (rl *RateLimiter) Wait(ctx context.Context, n int) error {
	if rl.waiter != nil {
		return rl.waiter.Wait(ctx, n)
	}
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
	rl.limiter.SetLimit(newLimit)
	if redisWaiter, ok := rl.waiter.(*RedisRateWaiter); ok {
		redisWaiter.SetLimit(newLimit)
	}
}

// SetBurst 设置突发值大小
func (rl *RateLimiter) SetBurst(newBurst int) {
	rl.limiter.SetBurst(newBurst)
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
	limiter *rate.Limiter
	logger  *slog.Logger
}

// Wait 在Redis中等待直到令牌可用或上下文被取消
func (rl *RedisRateWaiter) Wait(ctx context.Context, n int) error {
	if rl.limit == rate.Inf {
		rl.logger.Debug("Redis限流器: 无限速率，直接放行", "token_id", rl.tokenID)
		return nil
	}

	if rl.backend.client == nil {
		rl.logger.Warn("Redis限流器: Redis 客户端不可用，使用本地限速器作为备份", "token_id", rl.tokenID)
		return rl.limiter.WaitN(ctx, n)
	}
	script := redis.NewScript(`
	--[[
	令牌桶算法的Redis实现（优化版）
	功能：
	1. 分布式令牌桶限流
	2. 动态速率调整
	3. 最大等待时间限制
	4. 支持自动过期清理
	]]--
	
	--------------------------
	-- 常量与参数解析
	--------------------------
	local NANOSECONDS_PER_SECOND = 1000000000
	local MAX_WAIT_SECONDS = 10  -- 硬限制：最大等待10秒
	
	-- 输入参数
	local key = KEYS[1]                     -- Redis键（令牌桶ID）
	local requested = tonumber(ARGV[1])     -- 请求的令牌数
	local rate = tonumber(ARGV[2])          -- 每秒生成的令牌数
	local capacity = tonumber(ARGV[3])      -- 桶的容量（最大令牌数）
	local now = tonumber(ARGV[4])           -- 当前时间（纳秒）
	local ttl = tonumber(ARGV[5])           -- 键的TTL（秒）
	
	-- 计算最大等待时间（取10秒或填满空桶所需时间的较小值）
	local max_wait_seconds = math.min(MAX_WAIT_SECONDS, capacity / rate)
	local max_wait_ns = max_wait_seconds * NANOSECONDS_PER_SECOND
	
	--------------------------
	-- 函数定义
	--------------------------
	
	-- 初始化一个新令牌桶
	local function create_new_bucket()
	  return {
	    tokens = capacity,      -- 新桶默认填满令牌
	    last_update = now,      -- 更新时间为当前时间
	    last_rate = rate        -- 记录当前速率
	  }
	end
	
	-- 加载现有令牌桶状态
	local function load_bucket()
	  local bucket = redis.call('hmget', key, 'tokens', 'last_update', 'last_rate')
	  
	  -- 桶不存在，创建新桶
	  if bucket[1] == false then
	    return create_new_bucket()
	  end
	  
	  -- 解析桶状态
	  return {
	    tokens = tonumber(bucket[1]),
	    last_update = tonumber(bucket[2]),
	    last_rate = bucket[3] ~= false and tonumber(bucket[3]) or 0
	  }
	end
	
	-- 处理速率变化
	local function handle_rate_change(bucket)
	  local previous_rate = bucket.last_rate
	  
	  -- 检测有效的速率变化（>10%）
	  local significant_change = previous_rate > 0 and rate > 0 and
	                            math.abs(rate - previous_rate) / previous_rate > 0.1
	                            
	  -- 当速率显著降低时，调整令牌数以避免过长等待时间
	  if significant_change and rate < previous_rate and bucket.tokens < 0 then
	    -- 负债重置策略：限制最大负债为一秒产生的令牌数
	    bucket.tokens = math.max(bucket.tokens, -rate)
	  end
	  
	  return bucket
	end
	
	-- 更新令牌数（基于时间流逝）
	local function refill_tokens(bucket)
	  -- 计算经过的时间
	  local elapsed_ns = math.max(0, now - bucket.last_update)
	  local elapsed_seconds = elapsed_ns / NANOSECONDS_PER_SECOND
	  
	  -- 计算新增令牌
	  local new_tokens = elapsed_seconds * rate
	  
	  -- 更新桶状态
	  bucket.tokens = math.min(capacity, bucket.tokens + new_tokens)
	  bucket.last_update = now
	  bucket.last_rate = rate
	  
	  return bucket
	end
	
	-- 消费请求的令牌
	local function consume_tokens(bucket, tokens_needed)
	  -- 足够的令牌 - 立即通过
	  if bucket.tokens >= tokens_needed then
	    local result = {
	      allowed = 1,
	      wait_time = 0,
	      remaining_tokens = bucket.tokens - tokens_needed
	    }
	    return result
	  end
	  
	  -- 令牌不足 - 计算等待时间
	  local deficit = tokens_needed - bucket.tokens
	  local raw_wait_time = math.ceil(deficit * NANOSECONDS_PER_SECOND / rate)
	  local wait_time = math.min(raw_wait_time, max_wait_ns)
	  
	  -- 计算等待后状态
	  local actual_wait_seconds = wait_time / NANOSECONDS_PER_SECOND
	  local tokens_generated = actual_wait_seconds * rate
	  
	  -- 计算剩余令牌
	  local remaining_tokens
	  if wait_time >= max_wait_ns then
	    -- 达到最大等待时间，调整令牌计算
	    remaining_tokens = bucket.tokens + tokens_generated - tokens_needed
	  else
	    -- 正常情况，允许负债
	    remaining_tokens = bucket.tokens - tokens_needed
	  end
	  
	  local result = {
	    allowed = 0,
	    wait_time = wait_time,
	    remaining_tokens = remaining_tokens
	  }
	  return result
	end
	
	-- 保存桶状态到Redis
	local function save_bucket(tokens)
	  redis.call('hmset', key, 'tokens', tokens, 'last_update', now, 'last_rate', rate)
	  redis.call('expire', key, ttl)
	end
	
	--------------------------
	-- 主执行逻辑
	--------------------------
	
	-- 1. 加载桶状态
	local bucket = load_bucket()
	
	-- 2. 处理速率变化
	bucket = handle_rate_change(bucket)
	
	-- 3. 添加新生成的令牌
	bucket = refill_tokens(bucket)
	
	-- 4. 处理请求
	local result = consume_tokens(bucket, requested)
	
	-- 5. 保存更新后的状态
	save_bucket(result.remaining_tokens)
	
	-- 6. 返回结果
	return {result.allowed, result.wait_time}
	`)

	ratePerSecond := float64(rl.limit)
	rl.logger.Debug("Redis限流器: 调用 Lua 脚本",
		"token_id", rl.tokenID,
		"requested_tokens", n,
		"rate_per_second", ratePerSecond,
		"burst", rl.burst,
		"ttl_seconds", int(rl.backend.keyTTL.Seconds()))
	result, err := script.Run(ctx, rl.backend.client,
		[]string{rl.backend.getRedisKey(rl.tokenID)},
		n,
		ratePerSecond,
		rl.burst,
		time.Now().UnixNano(),
		int(rl.backend.keyTTL.Seconds()),
	).Result()

	rl.logger.Debug("Redis限流器: Lua 脚本原始返回", "token_id", rl.tokenID, "result", result, "error", err)
	if err != nil {
		rl.logger.Error("Redis限流器: 执行 Redis 脚本出错，使用本地限速器作为后备", "token_id", rl.tokenID, "error", err)
		return rl.limiter.WaitN(ctx, n)
	}

	results, ok := result.([]interface{})
	if !ok || len(results) != 2 {
		return fmt.Errorf("意外的Redis脚本返回结果")
	}

	allowed, ok := results[0].(int64)
	if !ok {
		return fmt.Errorf("无法解析Redis脚本返回的allowed值")
	}

	if allowed != 0 && allowed != 1 {
		return fmt.Errorf("意外的allowed值: %d", allowed)
	} else if allowed == 1 {
		rl.logger.Debug("Redis限流器: 有足够令牌，立即通过", "token_id", rl.tokenID, "requested_tokens", n)
		return nil
	}

	waitTime, ok := results[1].(int64)
	if !ok {
		return fmt.Errorf("无法解析Redis脚本返回的wait_time值")
	}
	rl.logger.Debug("Redis限流器: Lua 脚本解析后", "token_id", rl.tokenID, "allowed", allowed, "wait_time_ns", waitTime)
	waitDuration := time.Duration(waitTime)
	rl.logger.Debug("Redis限流器: 令牌不足，需要等待", "token_id", rl.tokenID, "requested_tokens", n, "wait_duration", waitDuration)
	timer := time.NewTimer(waitDuration)
	defer timer.Stop()

	select {
	case <-timer.C:
		rl.logger.Debug("Redis限流器: 等待完成，已放行", "token_id", rl.tokenID, "requested_tokens", n)
		return nil
	case <-ctx.Done():
		err := ctx.Err()
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
	rl.limiter.SetLimit(newLimit)
}

// SetBurst 设置突发值大小
func (rl *RedisRateWaiter) SetBurst(newBurst int) {
	rl.burst = newBurst
	rl.limiter.SetBurst(newBurst)
}
