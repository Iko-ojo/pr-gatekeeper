// Package capture turns raw sandbox artifacts (proxy logs, container diffs,
// file contents) into structured observations and model.Findings.
package capture

import (
	"bufio"
	"io"
	"net/url"
	"strings"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
)

// EgressEntry is a single outbound connection attempt recorded by the sandbox
// egress proxy.
type EgressEntry struct {
	Host    string `json:"host"`
	Allowed bool   `json:"allowed"`
	Raw     string `json:"raw,omitempty"`
}

// ParseSquidLog parses a Squid-format access log. Each line looks like:
//
//	1720000000.123 12 172.17.0.3 TCP_DENIED/403 3813 CONNECT evil.example:443 - HIER_NONE/- text/html
//
// A code containing "DENIED" marks a blocked attempt; anything else is treated
// as an allowed connection. The host is extracted from the request target.
func ParseSquidLog(r io.Reader) []EgressEntry {
	var entries []EgressEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		// Squid access lines begin with a unix timestamp (e.g. 1720000000.123).
		// This guard skips interleaved startup/cache messages when the log is
		// read from `docker logs`.
		if !looksLikeTimestamp(fields[0]) {
			continue
		}
		code := fields[3]
		target := fields[6]
		host := hostFromTarget(target)
		if host == "" {
			continue
		}
		entries = append(entries, EgressEntry{
			Host:    host,
			Allowed: !strings.Contains(strings.ToUpper(code), "DENIED"),
			Raw:     line,
		})
	}
	return entries
}

// looksLikeTimestamp reports whether s is a Squid-style epoch timestamp such as
// "1720000000.123": digits, optionally followed by a dot and more digits.
func looksLikeTimestamp(s string) bool {
	if s == "" {
		return false
	}
	seenDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			seenDigit = true
		case r == '.':
		default:
			return false
		}
	}
	return seenDigit
}

// hostFromTarget extracts a hostname from a Squid request target, which may be
// a full URL (http://host/path) or a host:port pair (CONNECT host:443).
func hostFromTarget(target string) string {
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	host := target
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.TrimSpace(host)
}

// EgressFindings converts denied egress attempts into findings. Allowed
// connections are not findings; they are retained in the evidence bundle.
func EgressFindings(entries []EgressEntry) []model.Finding {
	seen := map[string]bool{}
	var findings []model.Finding
	for _, e := range entries {
		if e.Allowed || seen[e.Host] {
			continue
		}
		seen[e.Host] = true
		findings = append(findings, model.Finding{
			Category: model.CategoryNetwork,
			Rule:     "egress.denied",
			Severity: model.SeverityBlock,
			Message:  "Workload attempted to reach a host outside the allow-list",
			Resource: e.Host,
		})
	}
	return findings
}
