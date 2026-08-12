// Command gatekeeper is the Agent PR Gatekeeper CLI. It runs a pull request
// through a sandboxed execution and static analysis, evaluates the result
// against policy, and publishes a merge verdict.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/capture"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/config"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/github"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/policy"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/report"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/sandbox"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/static"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runCmd(os.Args[2:]))
	case "init":
		os.Exit(initCmd(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("gatekeeper", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `gatekeeper - Agent PR Gatekeeper

Usage:
  gatekeeper run [flags]     Evaluate the current PR and post a verdict
  gatekeeper init [flags]    Write a starter gatekeeper.yaml
  gatekeeper version         Print the version

Run 'gatekeeper run -h' for run flags.`)
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "gatekeeper.yaml", "path to gatekeeper.yaml")
	workspace := fs.String("workspace", ".", "workspace directory to analyze")
	baseRef := fs.String("base-ref", envOr("GITHUB_BASE_REF", ""), "git base ref for the diff")
	outputDir := fs.String("output-dir", ".gatekeeper", "directory for the evidence bundle")
	forceAgent := fs.Bool("agent", false, "force the agent policy profile")
	noSandbox := fs.Bool("no-sandbox", envBool("GATEKEEPER_NO_SANDBOX", false), "skip Docker sandbox execution (static-only)")
	noPublish := fs.Bool("no-publish", false, "do not post results to GitHub")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	isAgent := *forceAgent || detectAgent()
	profileName := cfg.SelectProfileName(isAgent)
	profile, err := cfg.Resolve(profileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	absWorkspace, _ := filepath.Abs(*workspace)

	var findings []model.Finding
	bundle := report.Bundle{}

	// 1. Sandbox execution (behavioural evidence).
	if !*noSandbox {
		if sandbox.Available() {
			res, err := sandbox.NewRunner(cfg, absWorkspace).Run()
			if err != nil {
				fmt.Fprintln(os.Stderr, "sandbox error:", err)
			} else {
				findings = append(findings, capture.EgressFindings(res.Egress)...)
				findings = append(findings, capture.DiffFindings(res.OutsideWrites)...)
				findings = append(findings, capture.SecretFindings(capture.ScanText("command-output", res.Output))...)
				bundle.Egress = res.Egress
				bundle.Evidence.DeniedHosts = deniedHosts(res.Egress)
				bundle.Evidence.AllowedHosts = allowedHosts(res.Egress)
				bundle.Evidence.OutsideWrites = res.OutsideWrites
				for _, c := range res.Commands {
					bundle.Commands = append(bundle.Commands, report.CommandResult{Name: c.Name, ExitCode: c.ExitCode})
				}
			}
		} else {
			fmt.Fprintln(os.Stderr, "warning: docker unavailable, skipping sandbox (static-only run)")
		}
	}

	// 2. Static analysis over changed files (secret scan + IaC).
	changed := static.ChangedFiles(absWorkspace, *baseRef)
	secretHits := capture.ScanFiles(absPaths(absWorkspace, changed))
	findings = append(findings, capture.SecretFindings(secretHits)...)
	bundle.Evidence.SecretFiles = uniqueFiles(secretHits)

	iacFindings := static.NewAnalyzer(absWorkspace).Analyze(changed)
	findings = append(findings, iacFindings...)
	bundle.Evidence.ChangedIaCFile = iacFiles(changed)

	// 3. Policy evaluation.
	verdict := policy.Evaluate(findings, profile)
	bundle.Verdict = verdict

	// 4. Reporting.
	md := bundle.Markdown()
	fmt.Println(md)
	writeBundle(*outputDir, bundle, md)

	// 5. Publish to GitHub (optional).
	if !*noPublish {
		publish(verdict, md)
	}

	return verdict.ExitCode()
}

func publish(verdict model.Verdict, md string) {
	client, err := github.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "github init error:", err)
		return
	}
	if client == nil {
		return // no token; nothing to publish
	}
	headSHA := envOr("GITHUB_SHA", "")
	prNumber := github.PRNumberFromEnv()
	if err := client.Publish(headSHA, prNumber, verdict, md); err != nil {
		fmt.Fprintln(os.Stderr, "github publish error:", err)
	}
}

func writeBundle(dir string, bundle report.Bundle, md string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "output dir error:", err)
		return
	}
	if data, err := bundle.JSON(); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "evidence.json"), data, 0o644)
	}
	_ = os.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0o644)
}

// detectAgent reports whether the PR looks agent-authored, based on the GitHub
// Actions environment: a bot actor or an agent/* head branch.
func detectAgent() bool {
	actor := os.Getenv("GITHUB_ACTOR")
	if strings.HasSuffix(actor, "[bot]") || strings.HasSuffix(actor, "-bot") {
		return true
	}
	head := os.Getenv("GITHUB_HEAD_REF")
	return strings.HasPrefix(head, "agent/") || strings.HasPrefix(head, "bot/")
}

func initCmd(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	path := fs.String("path", "gatekeeper.yaml", "where to write the config")
	image := fs.String("image", "node:20", "workload image")
	_ = fs.Parse(args)

	if _, err := os.Stat(*path); err == nil {
		fmt.Fprintf(os.Stderr, "refusing to overwrite existing %s\n", *path)
		return 1
	}
	if err := os.WriteFile(*path, []byte(starterConfig(*image)), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("wrote %s\n", *path)
	return 0
}

func starterConfig(image string) string {
	return fmt.Sprintf(`image: %s
commands:
  build: npm ci
  test: npm test
network:
  allow:
    - github.com
    - registry.npmjs.org
policies:
  default:
    deny_network_outside_allowlist: true
    deny_writes_outside_workspace: true
    secret_scan: true
    iac:
      block_public_s3: true
  agent:
    inherit: default
    fail_on:
      - warn
`, image)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	default:
		return fallback
	}
}

func absPaths(root string, rel []string) []string {
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, filepath.Join(root, r))
	}
	return out
}

func iacFiles(changed []string) []string {
	var out []string
	for _, f := range changed {
		if strings.EqualFold(filepath.Ext(f), ".tf") {
			out = append(out, f)
		}
	}
	return out
}

func deniedHosts(entries []capture.EgressEntry) []string {
	return hostsByAllowed(entries, false)
}

func allowedHosts(entries []capture.EgressEntry) []string {
	return hostsByAllowed(entries, true)
}

func hostsByAllowed(entries []capture.EgressEntry, allowed bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if e.Allowed == allowed && !seen[e.Host] {
			seen[e.Host] = true
			out = append(out, e.Host)
		}
	}
	return out
}

func uniqueFiles(hits []capture.SecretHit) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hits {
		if !seen[h.File] {
			seen[h.File] = true
			out = append(out, h.File)
		}
	}
	return out
}
