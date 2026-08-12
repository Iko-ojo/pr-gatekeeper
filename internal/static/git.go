package static

import (
	"os/exec"
	"strings"
)

// ChangedFiles returns the paths changed between baseRef and HEAD using
// `git diff --name-only`, as paths relative to the repository root. When
// baseRef is empty it falls back to the files changed in the most recent
// commit. Because CI checkouts often only have the base branch under
// `origin/`, it tries a few ref spellings before giving up. On any error it
// returns nil, which callers treat as "scan nothing".
func ChangedFiles(dir, baseRef string) []string {
	var refSpecs []string
	if baseRef != "" {
		refSpecs = append(refSpecs, baseRef+"...HEAD", "origin/"+baseRef+"...HEAD")
	}
	refSpecs = append(refSpecs, "HEAD~1...HEAD")

	for _, spec := range refSpecs {
		out, err := exec.Command("git", "-C", dir, "diff", "--name-only", spec).Output()
		if err != nil {
			continue
		}
		return splitLines(string(out))
	}
	return nil
}

// RepoRoot returns the absolute path of the git repository containing dir, or
// an empty string when dir is not inside a git work tree.
func RepoRoot(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
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
