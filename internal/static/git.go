package static

import (
	"os/exec"
	"strings"
)

// ChangedFiles returns the paths changed between baseRef and the working tree
// using `git diff --name-only`. When baseRef is empty it falls back to the
// files changed in the most recent commit. On any error it returns nil, which
// callers treat as "scan nothing".
func ChangedFiles(dir, baseRef string) []string {
	args := []string{"-C", dir, "diff", "--name-only"}
	if baseRef != "" {
		args = append(args, baseRef+"...HEAD")
	} else {
		args = append(args, "HEAD~1...HEAD")
	}
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil
	}
	return splitLines(string(out))
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
