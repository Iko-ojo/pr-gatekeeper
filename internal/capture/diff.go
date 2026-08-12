package capture

import (
	"bufio"
	"io"
	"strings"

	"github.com/Iko-ojo/pr-gatekeeper/internal/model"
)

// WorkspaceMount is the path inside the workload container where the PR
// checkout is mounted. Writes under this path are expected; writes elsewhere
// are what we care about.
const WorkspaceMount = "/workspace"

// ParseDockerDiff parses `docker diff <container>` output and returns the paths
// that were added or changed outside the workspace mount. Deletions (prefix
// "D") are ignored because container teardown is expected to remove files.
func ParseDockerDiff(r io.Reader, workspace string) []string {
	if workspace == "" {
		workspace = WorkspaceMount
	}
	var paths []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if len(line) < 3 {
			continue
		}
		kind := line[0]
		path := strings.TrimSpace(line[1:])
		if kind != 'A' && kind != 'C' {
			continue
		}
		if path == workspace || strings.HasPrefix(path, workspace+"/") {
			continue
		}
		if isNoiseDir(path) {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

// isNoiseDir filters paths that a normal build legitimately writes to and that
// carry no signal about tampering: ephemeral system dirs and the build user's
// HOME (where npm, pip, go, etc. keep their caches). Writes to genuinely
// sensitive locations (/etc, /usr, /bin, ...) are still reported.
//
// This is an allow-list of expected write locations. A future version should
// invert this to an explicit deny-list of sensitive system paths so that, e.g.,
// a write to /root/.ssh/authorized_keys is caught while /root/.npm is not.
func isNoiseDir(path string) bool {
	noisy := []string{
		"/tmp", "/run", "/var/run", "/var/cache", "/var/log",
		"/proc", "/sys", "/dev",
		// Build-user HOME directories: package managers write caches, logs and
		// state here on every run, so these are expected, not suspicious.
		"/root", "/home",
	}
	for _, n := range noisy {
		if path == n || strings.HasPrefix(path, n+"/") {
			return true
		}
	}
	return false
}

// DiffFindings converts out-of-workspace writes into findings.
func DiffFindings(paths []string) []model.Finding {
	var findings []model.Finding
	for _, p := range paths {
		findings = append(findings, model.Finding{
			Category: model.CategoryFilesystem,
			Rule:     "write.outside_workspace",
			Severity: model.SeverityBlock,
			Message:  "Workload wrote to a path outside the mounted workspace",
			Resource: p,
		})
	}
	return findings
}
