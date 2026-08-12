package policy

import (
	"testing"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/config"
	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
)

func TestEvaluateBlocksOnEnabledRule(t *testing.T) {
	findings := []model.Finding{
		{Category: model.CategoryNetwork, Rule: "egress.denied", Resource: "evil.example"},
	}
	profile := config.ResolvedProfile{Name: "default", DenyNetworkOutsideAllowlist: true}
	v := Evaluate(findings, profile)
	if v.Decision != model.DecisionBlock {
		t.Fatalf("expected block, got %s", v.Decision)
	}
}

func TestEvaluateDropsDisabledRule(t *testing.T) {
	findings := []model.Finding{
		{Category: model.CategoryNetwork, Rule: "egress.denied", Resource: "evil.example"},
	}
	profile := config.ResolvedProfile{Name: "loose", DenyNetworkOutsideAllowlist: false}
	v := Evaluate(findings, profile)
	if v.Decision != model.DecisionPass {
		t.Fatalf("expected pass when rule disabled, got %s", v.Decision)
	}
	if len(v.Findings) != 0 {
		t.Errorf("expected findings dropped, got %+v", v.Findings)
	}
}

func TestFailOnWarnEscalates(t *testing.T) {
	findings := []model.Finding{
		{Category: model.CategoryIaC, Rule: "tfsec.aws-s3-x", Severity: model.SeverityWarn},
	}
	base := config.ResolvedProfile{Name: "default"}
	if v := Evaluate(findings, base); v.Decision != model.DecisionWarn {
		t.Fatalf("expected warn without fail_on, got %s", v.Decision)
	}
	strict := config.ResolvedProfile{Name: "agent", FailOnWarn: true}
	if v := Evaluate(findings, strict); v.Decision != model.DecisionBlock {
		t.Fatalf("expected block with fail_on warn, got %s", v.Decision)
	}
}

func TestEmptyFindingsPass(t *testing.T) {
	if v := Evaluate(nil, config.ResolvedProfile{Name: "default"}); v.Decision != model.DecisionPass {
		t.Fatalf("expected pass, got %s", v.Decision)
	}
}
