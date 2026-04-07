package payloads

import (
	"fmt"
	"net/url"
	"strings"
)

// AppendQueryParamSeedURLs добавляет URL вида base?<param>=<payload> (Katana и др.).
func AppendQueryParamSeedURLs(seeds []string, baseURL, paramName, payloadPath string, max int) ([]string, error) {
	if payloadPath == "" || max <= 0 {
		return seeds, nil
	}
	lines, err := LoadLines(payloadPath)
	if err != nil {
		return seeds, err
	}
	uBase, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || uBase.Scheme == "" || uBase.Host == "" {
		return seeds, fmt.Errorf("payloads: invalid baseURL %q", baseURL)
	}
	seen := make(map[string]struct{})
	for _, s := range seeds {
		seen[s] = struct{}{}
	}
	param := strings.TrimSpace(paramName)
	if param == "" {
		param = "q"
	}
	n := 0
	for _, line := range lines {
		if n >= max {
			break
		}
		u := *uBase
		q := u.Query()
		q.Set(param, line)
		u.RawQuery = q.Encode()
		su := u.String()
		if _, ok := seen[su]; ok {
			continue
		}
		seen[su] = struct{}{}
		seeds = append(seeds, su)
		n++
	}
	return seeds, nil
}
