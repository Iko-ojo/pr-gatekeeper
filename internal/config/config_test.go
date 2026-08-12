package config

import "testing"

const sample = `
image: node:20
commands:
  build: npm ci
  test: npm test
network:
  allow: [github.com, registry.npmjs.org]
policies:
  default:
    deny_network_outside_allowlist: true
    deny_writes_outside_workspace: true
    secret_scan: true
    iac:
      block_public_s3: true
  agent:
    inherit: default
    fail_on: [warn]
`

func TestParseAndOrderedCommands(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Image != "node:20" {
		t.Errorf("image = %q", cfg.Image)
	}
	cmds := cfg.Commands.Ordered()
	if len(cmds) != 2 || cmds[0].Name != "build" || cmds[1].Name != "test" {
		t.Errorf("ordered commands = %+v", cmds)
	}
}

func TestParseRejectsMissingDefault(t *testing.T) {
	_, err := Parse([]byte("image: x\npolicies:\n  agent: {}\n"))
	if err == nil {
		t.Fatal("expected error for missing default profile")
	}
}

func TestSelectProfileName(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.SelectProfileName(false); got != "default" {
		t.Errorf("non-agent profile = %q", got)
	}
	if got := cfg.SelectProfileName(true); got != "agent" {
		t.Errorf("agent profile = %q", got)
	}
}

func TestResolveInheritance(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	rp, err := cfg.Resolve("agent")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Inherited from default.
	if !rp.DenyNetworkOutsideAllowlist || !rp.SecretScan || !rp.BlockPublicS3 {
		t.Errorf("inherited toggles not set: %+v", rp)
	}
	// Own field.
	if !rp.FailOnWarn {
		t.Errorf("fail_on warn not resolved: %+v", rp)
	}
}

func TestResolveDetectsCycle(t *testing.T) {
	cfg, err := Parse([]byte(`
image: x
policies:
  default: { inherit: a }
  a: { inherit: b }
  b: { inherit: a }
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Resolve("a"); err == nil {
		t.Fatal("expected cycle error")
	}
}
