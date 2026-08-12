// Package e2e exercises the full evaluation pipeline (static analysis + secret
// scanning + policy) against a workspace on disk, without requiring Docker.
package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Iko-ojo/pr-gatekeeper/internal/capture"
	"github.com/Iko-ojo/pr-gatekeeper/internal/config"
	"github.com/Iko-ojo/pr-gatekeeper/internal/model"
	"github.com/Iko-ojo/pr-gatekeeper/internal/policy"
	"github.com/Iko-ojo/pr-gatekeeper/internal/report"
	"github.com/Iko-ojo/pr-gatekeeper/internal/static"
)

const cfgYAML = `
image: node:20
commands:
  test: npm test
network:
  allow: [github.com]
policies:
  default:
    deny_network_outside_allowlist: true
    deny_writes_outside_workspace: true
    secret_scan: true
    iac:
      block_public_s3: true
  agent:
    inherit: default
    fail_on: [warn]
`

// TestUnsafePRIsBlocked writes a workspace containing a public-S3 Terraform
// file and a committed AWS key, then runs the static + secret + policy layers
// and asserts the merge is blocked with both findings present.
func TestUnsafePRIsBlocked(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "infra/main.tf", `resource "aws_s3_bucket_acl" "x" {
  acl = "public-read"
}`)
	writeFile(t, dir, "config/leak.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")

	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	profile, err := cfg.Resolve(cfg.SelectProfileName(true))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	changed := []string{"infra/main.tf", "config/leak.env"}

	var findings []model.Finding
	findings = append(findings, capture.SecretFindings(capture.ScanFiles(absPaths(dir, changed)))...)
	findings = append(findings, static.NewAnalyzer(dir).Analyze(changed)...)

	verdict := policy.Evaluate(findings, profile)
	if verdict.Decision != model.DecisionBlock {
		t.Fatalf("expected block, got %s (findings: %+v)", verdict.Decision, verdict.Findings)
	}

	if !hasCategory(verdict.Findings, model.CategorySecret) {
		t.Errorf("missing secret finding: %+v", verdict.Findings)
	}
	if !hasCategory(verdict.Findings, model.CategoryIaC) {
		t.Errorf("missing IaC finding: %+v", verdict.Findings)
	}

	// The rendered report should reflect the block decision.
	md := report.Bundle{Verdict: verdict}.Markdown()
	if md == "" {
		t.Error("empty markdown report")
	}
}

// TestCleanPRPasses confirms a benign workspace yields a passing verdict.
func TestCleanPRPasses(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "infra/main.tf", `resource "aws_s3_bucket_acl" "x" {
  acl = "private"
}`)
	writeFile(t, dir, "src/app.js", "console.log('hello');\n")

	cfg, _ := config.Parse([]byte(cfgYAML))
	profile, _ := cfg.Resolve("default")

	changed := []string{"infra/main.tf", "src/app.js"}
	var findings []model.Finding
	findings = append(findings, capture.SecretFindings(capture.ScanFiles(absPaths(dir, changed)))...)
	findings = append(findings, static.NewAnalyzer(dir).Analyze(changed)...)

	if v := policy.Evaluate(findings, profile); v.Decision != model.DecisionPass {
		t.Fatalf("expected pass, got %s (%+v)", v.Decision, v.Findings)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func absPaths(root string, rel []string) []string {
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(root, r))
	}
	return out
}

func hasCategory(findings []model.Finding, cat model.Category) bool {
	for _, f := range findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}
