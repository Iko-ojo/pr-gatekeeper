package capture

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
)

// secretPattern is a named credential-shaped regex.
type secretPattern struct {
	rule string
	re   *regexp.Regexp
}

// secretPatterns is a deliberately small, high-signal set. It favours patterns
// with low false-positive rates over exhaustive coverage.
var secretPatterns = []secretPattern{
	{"secret.aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"secret.aws_secret_key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?`)},
	{"secret.private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"secret.github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{"secret.slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"secret.generic_api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`)},
}

// SecretHit is one credential-shaped match.
type SecretHit struct {
	Rule string `json:"rule"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// ScanText scans arbitrary text (used for command output and log capture).
func ScanText(label, text string) []SecretHit {
	return scan(label, strings.NewReader(text))
}

// ScanFiles scans each file for secret-shaped content, returning all hits.
func ScanFiles(paths []string) []SecretHit {
	var hits []SecretHit
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		hits = append(hits, scan(p, f)...)
		f.Close()
	}
	return hits
}

func scan(label string, r io.Reader) []SecretHit {
	var hits []SecretHit
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, p := range secretPatterns {
			if p.re.MatchString(line) {
				hits = append(hits, SecretHit{Rule: p.rule, File: label, Line: lineNo})
			}
		}
	}
	return hits
}

// SecretFindings converts secret hits into findings.
func SecretFindings(hits []SecretHit) []model.Finding {
	var findings []model.Finding
	for _, h := range hits {
		findings = append(findings, model.Finding{
			Category: model.CategorySecret,
			Rule:     h.Rule,
			Severity: model.SeverityBlock,
			Message:  "Potential credential detected in the change",
			Resource: h.File,
			Detail:   lineRef(h.Line),
		})
	}
	return findings
}

func lineRef(line int) string {
	if line <= 0 {
		return ""
	}
	return "line " + itoa(line)
}

// itoa avoids pulling strconv into hot paths for a single small conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
