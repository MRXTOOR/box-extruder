package queue

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestJobMessageJSON(t *testing.T) {
	msg := JobMessage{
		JobID:      "job-123",
		UserID:     "user-456",
		TargetURL:  "https://example.com",
		ConfigYAML: "scans:\n  - name: test",
		ConfigHash: "abc123",
		Priority:   1,
		CreatedAt:  time.Now().Unix(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded JobMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.JobID != msg.JobID {
		t.Errorf("expected JobID %s, got %s", msg.JobID, decoded.JobID)
	}
	if decoded.TargetURL != msg.TargetURL {
		t.Errorf("expected TargetURL %s, got %s", msg.TargetURL, decoded.TargetURL)
	}
}

func TestConfig_Addr(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"localhost", 6379, "localhost:6379"},
		{"redis", 6380, "redis:6380"},
		{"", 0, ":6379"},
	}

	for _, tt := range tests {
		cfg := Config{Host: tt.host, Port: tt.port}
		got := cfg.Addr()
		if got != tt.want {
			t.Errorf("Addr() = %v, want %v", got, tt.want)
		}
	}
}

func TestConfig_Addr_DefaultPort(t *testing.T) {
	cfg := Config{Host: "localhost", Port: 0}
	if got := cfg.Addr(); got != "localhost:6379" {
		t.Errorf("Addr() = %v, want localhost:6379", got)
	}
}

func TestEnqueue_Dequeue(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	ctx := context.Background()

	if err := client.Ping(ctx).Err(); err == nil {
		defer func() {
			client.Del(ctx, ScanQueueKey)
			client.Close()
		}()

		msg := JobMessage{
			JobID:     "test-job-1",
			UserID:    "user-1",
			TargetURL: "https://test.com",
		}

		if err := Enqueue(ctx, client, msg); err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}

		dequeued, err := Dequeue(ctx, client, 5*time.Second)
		if err != nil {
			t.Fatalf("Dequeue failed: %v", err)
		}

		if dequeued.JobID != msg.JobID {
			t.Errorf("expected JobID %s, got %s", msg.JobID, dequeued.JobID)
		}
		if dequeued.TargetURL != msg.TargetURL {
			t.Errorf("expected TargetURL %s, got %s", msg.TargetURL, dequeued.TargetURL)
		}
	}
}

func TestGetQueueLen(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	ctx := context.Background()

	if err := client.Ping(ctx).Err(); err == nil {
		defer func() {
			client.Del(ctx, ScanQueueKey)
			client.Close()
		}()

		client.Del(ctx, ScanQueueKey)

		length, err := GetQueueLen(ctx, client)
		if err != nil {
			t.Fatalf("GetQueueLen failed: %v", err)
		}
		if length != 0 {
			t.Errorf("expected empty queue, got %d", length)
		}

		msg := JobMessage{JobID: "test-job", UserID: "u", TargetURL: "t"}
		Enqueue(ctx, client, msg)

		length, _ = GetQueueLen(ctx, client)
		if length != 1 {
			t.Errorf("expected queue length 1, got %d", length)
		}
	}
}
