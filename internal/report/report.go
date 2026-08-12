// Package report renders a verdict and its supporting evidence into a JSON
// bundle (for archival/machine use) and Markdown (for the PR comment and Check
// Run summary).
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/capture"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
)

// Bundle is the complete, serializable record of a gatekeeper run.
type Bundle struct {
	Verdict  model.Verdict         `json:"verdict"`
	Evidence Evidence              `json:"evidence"`
	Commands []CommandResult       `json:"commands,omitempty"`
	Egress   []capture.EgressEntry `json:"egress,omitempty"`
}

// Evidence holds the raw observations behind the findings.
type Evidence struct {
	DeniedHosts    []string `json:"denied_hosts,omitempty"`
	AllowedHosts   []string `json:"allowed_hosts,omitempty"`
	OutsideWrites  []string `json:"outside_writes,omitempty"`
	SecretFiles    []string `json:"secret_files,omitempty"`
	ChangedIaCFile []string `json:"changed_iac_files,omitempty"`
}

// CommandResult records the outcome of one lifecycle command.
type CommandResult struct {
	Name     string `json:"name"`
	ExitCode int    `json:"exit_code"`
}

// JSON serializes the bundle as indented JSON.
func (b Bundle) JSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// Markdown renders a human-readable report suitable for a PR comment.
func (b Bundle) Markdown() string {
	var sb strings.Builder
	sb.WriteString("## Agent PR Gatekeeper\n\n")
	sb.WriteString(fmt.Sprintf("**Verdict:** %s  \n", verdictBadge(b.Verdict.Decision)))
	sb.WriteString(fmt.Sprintf("**Profile:** `%s`\n\n", b.Verdict.Profile))

	if len(b.Verdict.Findings) == 0 {
		sb.WriteString("No policy violations detected. :white_check_mark:\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("Found %d issue(s):\n\n", len(b.Verdict.Findings)))
	sb.WriteString("| Severity | Category | Rule | Resource | Message |\n")
	sb.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, f := range b.Verdict.Findings {
		resource := f.Resource
		if f.Detail != "" {
			resource = strings.TrimSpace(resource + " " + f.Detail)
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | `%s` | `%s` | %s |\n",
			severityBadge(f.Severity), f.Category, f.Rule, resource, f.Message))
	}
	return sb.String()
}

func verdictBadge(d model.Decision) string {
	switch d {
	case model.DecisionBlock:
		return ":no_entry: BLOCK"
	case model.DecisionWarn:
		return ":warning: WARN"
	default:
		return ":white_check_mark: PASS"
	}
}

func severityBadge(s model.Severity) string {
	switch s {
	case model.SeverityBlock:
		return ":no_entry:"
	case model.SeverityWarn:
		return ":warning:"
	default:
		return ":information_source:"
	}
}
