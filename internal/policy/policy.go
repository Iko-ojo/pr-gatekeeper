// Package policy applies a resolved profile to raw findings and produces the
// final verdict. The capture and static layers propose findings; this package
// is the sole authority on whether each one is kept, at what severity, and what
// the overall decision is.
package policy

import (
	"strings"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/config"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
)

// Evaluate filters and grades findings under the resolved profile, then rolls
// them up into a verdict.
func Evaluate(findings []model.Finding, profile config.ResolvedProfile) model.Verdict {
	kept := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		enabled, severity := grade(f, profile)
		if !enabled {
			continue
		}
		f.Severity = severity
		if profile.FailOnWarn && f.Severity == model.SeverityWarn {
			f.Severity = model.SeverityBlock
		}
		kept = append(kept, f)
	}

	return model.Verdict{
		Decision: decide(kept),
		Profile:  profile.Name,
		Findings: kept,
	}
}

// grade reports whether a finding's rule is enabled under the profile and, if
// so, the severity to assign it. A disabled toggle drops the finding entirely.
func grade(f model.Finding, p config.ResolvedProfile) (bool, model.Severity) {
	switch f.Category {
	case model.CategoryNetwork:
		return p.DenyNetworkOutsideAllowlist, model.SeverityBlock
	case model.CategoryFilesystem:
		return p.DenyWritesOutsideWorkspace, model.SeverityBlock
	case model.CategorySecret:
		return p.SecretScan, model.SeverityBlock
	case model.CategoryIaC:
		if strings.HasPrefix(f.Rule, "iac.public_s3") {
			return p.BlockPublicS3, model.SeverityBlock
		}
		// External scanner findings (e.g. tfsec.*) are always reported; they
		// keep whatever severity the scanner adapter assigned.
		return true, f.Severity
	default:
		return true, f.Severity
	}
}

// decide returns the highest-severity outcome present in the kept findings.
func decide(findings []model.Finding) model.Decision {
	decision := model.DecisionPass
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityBlock:
			return model.DecisionBlock
		case model.SeverityWarn:
			decision = model.DecisionWarn
		}
	}
	return decision
}
