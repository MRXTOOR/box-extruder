package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
}

func Connect(cfg Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Config) Addr() string {
	port := c.Port
	if port == 0 {
		port = 6379
	}
	return fmt.Sprintf("%s:%d", c.Host, port)
}

type JobMessage struct {
	JobID      string `json:"jobId"`
	UserID     string `json:"userId"`
	TargetURL  string `json:"targetUrl"`
	ConfigYAML string `json:"configYaml"`
	ConfigHash string `json:"configHash"`
	Priority   int    `json:"priority"`
	CreatedAt  int64  `json:"createdAt"`
}

const ScanQueueKey = "dast:scan:queue"
const CancelKeyPrefix = "dast:scan:cancel:"

func Enqueue(ctx context.Context, rdb *redis.Client, job JobMessage) error {
	job.CreatedAt = time.Now().Unix()
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return rdb.LPush(ctx, ScanQueueKey, data).Err()
}

func Dequeue(ctx context.Context, rdb *redis.Client, timeout time.Duration) (*JobMessage, error) {
	result, err := rdb.BRPop(ctx, timeout, ScanQueueKey).Result()
	if err != nil {
		return nil, err
	}
	var job JobMessage
	if err := json.Unmarshal([]byte(result[1]), &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func GetQueueLen(ctx context.Context, rdb *redis.Client) (int64, error) {
	return rdb.LLen(ctx, ScanQueueKey).Result()
}

func SetCancelFlag(ctx context.Context, rdb *redis.Client, jobID string) error {
	return rdb.Set(ctx, CancelKeyPrefix+jobID, "1", 24*time.Hour).Err()
}

func GetCancelFlag(ctx context.Context, rdb *redis.Client, jobID string) (bool, error) {
	result, err := rdb.Get(ctx, CancelKeyPrefix+jobID).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return result == "1", nil
}

func ClearCancelFlag(ctx context.Context, rdb *redis.Client, jobID string) error {
	return rdb.Del(ctx, CancelKeyPrefix+jobID).Err()
}
