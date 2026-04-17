package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Monitor struct {
	containers []string
}

type ContainerStatus struct {
	Name       string    `json:"name"`
	Image      string    `json:"image"`
	Status     string    `json:"status"`
	State      string    `json:"state"`
	Health     string    `json:"health"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	ExitCode   int       `json:"exitCode"`
	OOMKilled  bool      `json:"oomKilled"`
	Restarting bool      `json:"restarting"`
}

func NewMonitor(containers []string) (*Monitor, error) {
	return &Monitor{containers: containers}, nil
}

func (m *Monitor) Close() {}

func (m *Monitor) Ping(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "info")
	return cmd.Run()
}

func (m *Monitor) GetContainersStatus(ctx context.Context) ([]ContainerStatus, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var results []ContainerStatus

	for _, line := range lines {
		if line == "" {
			continue
		}

		var ps struct {
			Names     string `json:"Names"`
			Image     string `json:"Image"`
			Status    string `json:"Status"`
			State     string `json:"State"`
			StartedAt string `json:"StartedAt"`
			ExitCode  string `json:"ExitCode"`
		}

		if err := json.Unmarshal([]byte(line), &ps); err != nil {
			continue
		}

		status := ContainerStatus{
			Name:   ps.Names,
			Image:  ps.Image,
			Status: ps.Status,
			State:  ps.State,
			Health: m.getHealth(ps.State, ps.Status),
		}

		if ps.StartedAt != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", ps.StartedAt); err == nil {
				status.StartedAt = t
			}
		}

		if ps.ExitCode != "" {
			fmt.Sscanf(ps.ExitCode, "%d", &status.ExitCode)
		}

		status.Restarting = strings.Contains(ps.Status, "Restarting")

		results = append(results, status)
	}

	return results, nil
}

func (m *Monitor) getHealth(state, status string) string {
	switch state {
	case "running":
		if strings.Contains(status, "Up") {
			return "healthy"
		}
		return "starting"
	case "exited":
		return "stopped"
	case "restarting":
		return "restarting"
	case "dead":
		return "dead"
	default:
		return "unknown"
	}
}

func (m *Monitor) GetContainerLogs(ctx context.Context, name string, lines int) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", fmt.Sprintf("%d", lines), name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker logs: %w", err)
	}
	return string(output), nil
}

func (m *Monitor) GetContainerStats(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{json .}}", name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker stats: %w", err)
	}
	return string(output), nil
}
