// Package model holds the shared types that flow between the capture, static,
// policy and report layers. Keeping them here avoids import cycles between
// those packages.
package model

// Severity describes how a finding influences the merge verdict.
type Severity string

const (
	// SeverityInfo is informational only and never blocks a merge.
	SeverityInfo Severity = "info"
	// SeverityWarn surfaces a concern but only blocks when a profile opts in
	// via fail_on.
	SeverityWarn Severity = "warn"
	// SeverityBlock always fails the gate.
	SeverityBlock Severity = "block"
)

// rank gives an orderable value for a severity so the highest one can win.
func (s Severity) rank() int {
	switch s {
	case SeverityBlock:
		return 3
	case SeverityWarn:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool {
	return s.rank() >= other.rank()
}

// Category groups findings by the subsystem that produced them.
type Category string

const (
	// CategoryNetwork covers egress behaviour observed in the sandbox.
	CategoryNetwork Category = "network"
	// CategoryFilesystem covers writes outside the mounted workspace.
	CategoryFilesystem Category = "filesystem"
	// CategorySecret covers leaked-credential detections.
	CategorySecret Category = "secret"
	// CategoryIaC covers infrastructure-as-code static checks.
	CategoryIaC Category = "iac"
)

// Finding is a single observation from any layer. The capture and static layers
// emit findings with a proposed severity; the policy layer is the final
// authority and may drop or escalate them based on the active profile.
type Finding struct {
	Category Category `json:"category"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail,omitempty"`
	Resource string   `json:"resource,omitempty"`
}

// Decision is the top-level outcome of a gatekeeper run.
type Decision string

const (
	// DecisionPass means nothing actionable was found.
	DecisionPass Decision = "pass"
	// DecisionWarn means concerns exist but the merge is not blocked.
	DecisionWarn Decision = "warn"
	// DecisionBlock means the merge must not proceed.
	DecisionBlock Decision = "block"
)

// Verdict is the evaluated result the reporter renders and the CLI turns into
// an exit code.
type Verdict struct {
	Decision Decision  `json:"decision"`
	Profile  string    `json:"profile"`
	Findings []Finding `json:"findings"`
}

// ExitCode maps a decision to a process exit code. Block fails CI; warn and
// pass succeed so warnings do not break the build unless a profile escalated
// them to block first.
func (v Verdict) ExitCode() int {
	if v.Decision == DecisionBlock {
		return 1
	}
	return 0
}
