// Package sandbox executes a PR's lifecycle commands inside Docker containers
// with egress restricted to an allow-list, and captures the behavioural
// evidence (denied hosts, out-of-workspace writes, command output).
//
// Topology:
//
//	workload container ── internal network ──> egress proxy ──> internet
//
// The workload joins only an `--internal` Docker network, so it has no route to
// the internet except through the Squid proxy, which enforces the allow-list
// and logs every attempt. The proxy is additionally attached to the default
// bridge network to reach allowed hosts.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iko-ojo/pr-gatekeeper/internal/capture"
	"github.com/Iko-ojo/pr-gatekeeper/internal/config"
)

// proxyPort is the port Squid listens on inside the sandbox network.
const proxyPort = "3128"

// CommandResult records the outcome of one lifecycle command.
type CommandResult struct {
	Name     string
	ExitCode int
}

// Result is everything the capture layer needs from a sandbox run.
type Result struct {
	Egress        []capture.EgressEntry
	OutsideWrites []string
	Commands      []CommandResult
	Output        string
}

// Runner executes a config in Docker. The exec function is injectable for
// tests; production uses execCommand.
type Runner struct {
	cfg       *config.Config
	workspace string
	runID     string
	exec      func(name string, args ...string) (string, error)
}

// NewRunner creates a Runner for the given config and workspace directory.
func NewRunner(cfg *config.Config, workspace string) *Runner {
	return &Runner{
		cfg:       cfg,
		workspace: workspace,
		runID:     fmt.Sprintf("%d", time.Now().UnixNano()),
		exec:      execCommand,
	}
}

// Available reports whether the docker CLI is usable.
func Available() bool {
	_, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	out, err := execCommand("docker", "info", "--format", "{{.ServerVersion}}")
	return err == nil && strings.TrimSpace(out) != ""
}

func execCommand(name string, args ...string) (string, error) {
	var buf strings.Builder
	cmd := exec.Command(name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// Run provisions the network and containers, executes the lifecycle commands,
// collects evidence, and tears everything down.
func (r *Runner) Run() (*Result, error) {
	netName := "gk-net-" + r.runID
	proxyName := "gk-proxy-" + r.runID
	workName := "gk-work-" + r.runID

	confDir, err := os.MkdirTemp("", "gk-squid-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(confDir)

	confPath := filepath.Join(confDir, "squid.conf")
	if err := os.WriteFile(confPath, []byte(r.squidConf()), 0o644); err != nil {
		return nil, fmt.Errorf("write squid conf: %w", err)
	}

	defer r.cleanup(netName, proxyName, workName)

	if _, err := r.exec("docker", "network", "create", "--internal", netName); err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}

	// Start the proxy on the internal network, then also connect it to the
	// default bridge so it (and only it) can reach allowed hosts.
	if _, err := r.exec("docker", "run", "-d", "--name", proxyName,
		"--network", netName,
		"-v", confPath+":/etc/squid/squid.conf:ro",
		"ubuntu/squid:latest"); err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	if _, err := r.exec("docker", "network", "connect", "bridge", proxyName); err != nil {
		return nil, fmt.Errorf("connect proxy to bridge: %w", err)
	}

	result := &Result{}
	proxyURL := fmt.Sprintf("http://%s:%s", proxyName, proxyPort)
	script := r.commandScript()

	out, runErr := r.exec("docker", "run", "--name", workName,
		"--network", netName,
		"-e", "HTTP_PROXY="+proxyURL,
		"-e", "HTTPS_PROXY="+proxyURL,
		"-e", "http_proxy="+proxyURL,
		"-e", "https_proxy="+proxyURL,
		"-v", r.workspace+":"+capture.WorkspaceMount,
		"-w", capture.WorkspaceMount,
		r.cfg.Image, "sh", "-c", script)
	result.Output = out
	result.Commands = []CommandResult{{Name: "lifecycle", ExitCode: exitCodeOf(runErr)}}

	// Collect egress log from the proxy stdout.
	if logs, err := r.exec("docker", "logs", proxyName); err == nil {
		result.Egress = capture.ParseSquidLog(strings.NewReader(logs))
	}

	// Collect filesystem changes made outside the mounted workspace.
	if diff, err := r.exec("docker", "diff", workName); err == nil {
		result.OutsideWrites = capture.ParseDockerDiff(strings.NewReader(diff), capture.WorkspaceMount)
	}

	return result, nil
}

// commandScript joins the configured lifecycle commands into a single shell
// script that stops at the first failure.
func (r *Runner) commandScript() string {
	var parts []string
	for _, c := range r.cfg.Commands.Ordered() {
		parts = append(parts, fmt.Sprintf("echo '=== %s ==='", c.Name), c.Script)
	}
	if len(parts) == 0 {
		return "true"
	}
	return "set -e; " + strings.Join(parts, "; ")
}

// squidConf renders a Squid config that allows only the configured domains and
// logs every request (allowed or denied) to stdout.
func (r *Runner) squidConf() string {
	var b strings.Builder
	b.WriteString("http_port " + proxyPort + "\n")
	b.WriteString("access_log stdio:/dev/stdout squid\n")
	b.WriteString("cache_log /dev/null\n")
	if len(r.cfg.Network.Allow) > 0 {
		b.WriteString("acl allowed_domains dstdomain")
		for _, d := range r.cfg.Network.Allow {
			b.WriteString(" ." + strings.TrimPrefix(d, "."))
		}
		b.WriteString("\n")
		b.WriteString("http_access allow allowed_domains\n")
	}
	b.WriteString("http_access deny all\n")
	return b.String()
}

func (r *Runner) cleanup(netName, proxyName, workName string) {
	r.exec("docker", "rm", "-f", workName)
	r.exec("docker", "rm", "-f", proxyName)
	r.exec("docker", "network", "rm", netName)
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if ok := asExitError(err, &exitErr); ok {
		return exitErr.ExitCode()
	}
	return 1
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}
