package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	lru "github.com/hashicorp/golang-lru"
)

const (
	parseErrorRetryDelay = 10 * time.Millisecond
	zeroRetryWaitDelay   = 5 * time.Millisecond
	maxJitterMillis      = 10
	limiterCacheSize     = 10000
)

type RedisCellLimiter struct {
	client   *redis.Client
	key      string // 添加 key 字段
	capacity int64
	rate     int64
}

// NewRedisCellLimiter 现在接收 key 参数
func NewRedisCellLimiter(client *redis.Client, key string, capacity int64, rate int64) (*RedisCellLimiter, error) {
	return &RedisCellLimiter{
		client:   client,
		key:      key, // 存储 key
		capacity: capacity,
		rate:     rate,
	}, nil
}

// WaitN 不再需要 key 参数
func (l *RedisCellLimiter) WaitN(ctx context.Context, n int64) error {
	period := int64(1)

	redisStateMutex.RLock()
	if isRedisDown && time.Since(redisDownSince) < redisCooldownDuration {
		redisStateMutex.RUnlock()
		return nil
	}
	redisStateMutex.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// 使用存储在 limiter 实例中的 l.key
		result, err := l.client.Do(ctx, "CL.THROTTLE", l.key, l.capacity, l.rate, period, n).Result()
		if err != nil {
			if redisErr, ok := err.(redis.Error); ok && strings.Contains(strings.ToLower(redisErr.Error()), "unknown command") {
				return fmt.Errorf("redis-cell 模块不可用或 CL.THROTTLE 命令未知: %w", err)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			redisStateMutex.Lock()
			if !isRedisDown {
				isRedisDown = true
				redisDownSince = time.Now()
			} else {
				if time.Since(redisDownSince) >= redisCooldownDuration {
					redisDownSince = time.Now()
				}
			}
			redisStateMutex.Unlock()
			return nil
		} else {
			redisStateMutex.Lock()
			if isRedisDown {
				isRedisDown = false
			}
			redisStateMutex.Unlock()
		}
		reply, ok := result.([]interface{})
		if !ok || len(reply) < 5 {
			select {
			case <-time.After(parseErrorRetryDelay):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		allowed, ok1 := reply[0].(int64)
		retryAfter, ok2 := reply[3].(int64)
		if !ok1 || !ok2 {
			select {
			case <-time.After(parseErrorRetryDelay):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if allowed == 0 {
			return nil
		}
		if retryAfter < 0 {
			return fmt.Errorf("请求的字节数 (%d) 超过了限速器容量 (%d)", n, l.capacity)
		}
		if retryAfter == 0 {
			select {
			case <-time.After(zeroRetryWaitDelay):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		waitDuration := time.Duration(retryAfter) * time.Second
		jitter := time.Duration(rand.Intn(maxJitterMillis)) * time.Millisecond
		effectiveWait := waitDuration + jitter
		timer := time.NewTimer(effectiveWait)
		select {
		case <-timer.C:
			continue
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		}
	}
}

// Wait 不再需要 key 参数
func (l *RedisCellLimiter) Wait(ctx context.Context) error {
	return l.WaitN(ctx, 1) // 调用修改后的 WaitN
}

var (
	userLimitersCache     *lru.Cache
	limiterMutex          sync.RWMutex
	managerRedisClient    *redis.Client
	isRedisDown           bool = false
	redisDownSince        time.Time
	redisStateMutex       sync.RWMutex
	redisCooldownDuration = 5 * time.Minute
)

func InitBandwidthManager(opts *redis.Options) error {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	var err error
	userLimitersCache, _ = lru.New(limiterCacheSize) // Ignore error for simplicity as requested
	client := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err = client.Ping(pingCtx).Result(); err != nil {
		fmt.Printf("无法连接到 Redis (Addr=%s): %v\n", opts.Addr, err)
		_ = client.Close()
	}
	cmdCtx, cancelCmd := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelCmd()
	cmdInfo, err := client.Do(cmdCtx, "COMMAND", "INFO", "CL.THROTTLE").Result()
	if err != nil || cmdInfo == nil {
		isEmptyArray := false
		if err == nil && cmdInfo != nil {
			if infoSlice, ok := cmdInfo.([]interface{}); ok && len(infoSlice) == 0 {
				isEmptyArray = true
			}
		}
		if err == redis.Nil || isEmptyArray || (err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)) {
			fmt.Println("redis 服务器似乎不支持 CL.THROTTLE 命令 (Redis-Cell 模块未加载?)")
			_ = client.Close()
		} else if err != nil {
			fmt.Printf("检查 CL.THROTTLE 命令时发生错误: %v\n", err)
			_ = client.Close()
		}
	}
	managerRedisClient = client
	return nil
}

func GetOrCreateLimiter(userID string, requiredByteRate int64) (*RedisCellLimiter, error) {
	limiterMutex.RLock()
	if cachedLimiter, ok := userLimitersCache.Get(userID); ok {
		limiter, typeOk := cachedLimiter.(*RedisCellLimiter)
		if typeOk && limiter.rate == requiredByteRate {
			limiterMutex.RUnlock()
			return limiter, nil
		}
	}
	limiterMutex.RUnlock()
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	if cachedLimiter, ok := userLimitersCache.Get(userID); ok {
		limiter, typeOk := cachedLimiter.(*RedisCellLimiter)
		if typeOk && limiter.rate == requiredByteRate {
			return limiter, nil
		}
	}
	client := managerRedisClient
	// 创建 Limiter 时传递 userID 作为 key
	newLImiter, _ := NewRedisCellLimiter(client, userID, requiredByteRate, requiredByteRate) // Ignore error for simplicity as requested
	userLimitersCache.Add(userID, newLImiter)
	return newLImiter, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
