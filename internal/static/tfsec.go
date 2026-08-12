package static

import (
	"encoding/json"

	"github.com/Iko-ojo/pr-gatekeeper/internal/model"
)

// tfsecReport is the subset of tfsec's JSON output we consume.
type tfsecReport struct {
	Results []tfsecResult `json:"results"`
}

type tfsecResult struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Location    struct {
		Filename  string `json:"filename"`
		StartLine int    `json:"start_line"`
	} `json:"location"`
}

// runTfsec invokes tfsec with JSON output and normalizes its results into
// findings. Any execution or parse error yields no findings; tfsec is an
// optional enrichment, not a hard dependency.
func (a *Analyzer) runTfsec() []model.Finding {
	out, err := a.runner("tfsec", a.Dir, "--format", "json", "--no-color")
	if err != nil && len(out) == 0 {
		return nil
	}
	var report tfsecReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil
	}
	var findings []model.Finding
	for _, r := range report.Results {
		findings = append(findings, model.Finding{
			Category: model.CategoryIaC,
			Rule:     "tfsec." + r.RuleID,
			Severity: mapTfsecSeverity(r.Severity),
			Message:  r.Description,
			Resource: r.Location.Filename,
			Detail:   lineRef(r.Location.StartLine),
		})
	}
	return findings
}

// mapTfsecSeverity maps tfsec severities to our model. CRITICAL/HIGH block;
// everything else is a warning that only fails when a profile opts in.
func mapTfsecSeverity(s string) model.Severity {
	switch s {
	case "CRITICAL", "HIGH":
		return model.SeverityBlock
	case "MEDIUM":
		return model.SeverityWarn
	default:
		return model.SeverityInfo
	}
}

func lineRef(line int) string {
	if line <= 0 {
		return ""
	}
	return "line " + itoa(line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
