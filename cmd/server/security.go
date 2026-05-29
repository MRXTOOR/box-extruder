package main

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type loginAttemptLimiter struct {
	maxAttempts int
	window      time.Duration
	mu          sync.Mutex
	entries     map[string]loginAttemptEntry
}

type loginAttemptEntry struct {
	count     int
	expiresAt time.Time
}

func newLoginAttemptLimiter(maxAttempts int, window time.Duration) *loginAttemptLimiter {
	return &loginAttemptLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		entries:     make(map[string]loginAttemptEntry),
	}
}

func (l *loginAttemptLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || now.After(e.expiresAt) {
		delete(l.entries, key)
		return true
	}
	return e.count < l.maxAttempts
}

func (l *loginAttemptLimiter) fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || now.After(e.expiresAt) {
		l.entries[key] = loginAttemptEntry{count: 1, expiresAt: now.Add(l.window)}
		return
	}
	e.count++
	l.entries[key] = e
}

func (l *loginAttemptLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func remoteAddrKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return strings.TrimSpace(remoteAddr)
	}
	return strings.TrimSpace(host)
}

func validateDiscoverTargetURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid target URL")
	}
	host := strings.TrimSpace(strings.ToLower(u.Hostname()))
	if host == "" {
		return fmt.Errorf("invalid target URL host")
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return fmt.Errorf("localhost/private targets are not allowed")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("private or reserved target IP is not allowed")
		}
	}
	return nil
}
