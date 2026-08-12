package capture

import (
	"bufio"
	"io"
	"strings"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
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

// isNoiseDir filters ephemeral system paths that every container touches and
// that carry no signal about the change under review.
func isNoiseDir(path string) bool {
	noisy := []string{"/tmp", "/run", "/var/run", "/var/cache", "/var/log", "/proc", "/sys", "/dev", "/root/.cache", "/home"}
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
