// Package config loads and validates the gatekeeper.yaml file and resolves the
// effective policy profile for a given pull request.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level gatekeeper.yaml document.
type Config struct {
	// Image is the OCI image used for the workload container.
	Image string `yaml:"image"`
	// Commands are the lifecycle steps executed inside the sandbox.
	Commands Commands `yaml:"commands"`
	// Network configures the egress allow-list.
	Network Network `yaml:"network"`
	// Policies maps a profile name (e.g. "default", "agent") to its profile.
	Policies map[string]Profile `yaml:"policies"`
}

// Commands are the shell steps run in the workload container, in order.
type Commands struct {
	Build string `yaml:"build"`
	Test  string `yaml:"test"`
	Smoke string `yaml:"smoke"`
}

// Ordered returns the non-empty commands in execution order with a label.
func (c Commands) Ordered() []LabeledCommand {
	var out []LabeledCommand
	if c.Build != "" {
		out = append(out, LabeledCommand{Name: "build", Script: c.Build})
	}
	if c.Test != "" {
		out = append(out, LabeledCommand{Name: "test", Script: c.Test})
	}
	if c.Smoke != "" {
		out = append(out, LabeledCommand{Name: "smoke", Script: c.Smoke})
	}
	return out
}

// LabeledCommand pairs a lifecycle name with the script to run.
type LabeledCommand struct {
	Name   string
	Script string
}

// Network holds the outbound allow-list. Any host not listed is denied by the
// sandbox egress proxy and recorded.
type Network struct {
	Allow []string `yaml:"allow"`
}

// Profile is a set of policy toggles. Pointers distinguish "unset" (inherit)
// from an explicit false.
type Profile struct {
	// Inherit names another profile whose values fill any unset fields.
	Inherit string `yaml:"inherit"`

	DenyNetworkOutsideAllowlist *bool     `yaml:"deny_network_outside_allowlist"`
	DenyWritesOutsideWorkspace  *bool     `yaml:"deny_writes_outside_workspace"`
	SecretScan                  *bool     `yaml:"secret_scan"`
	IaC                         *IaCRules `yaml:"iac"`

	// FailOn lists severities that should be escalated to a hard block for this
	// profile (e.g. ["warn"]).
	FailOn []string `yaml:"fail_on"`
}

// IaCRules holds infrastructure-as-code policy toggles.
type IaCRules struct {
	BlockPublicS3 *bool `yaml:"block_public_s3"`
}

// Load reads and parses a gatekeeper.yaml file from path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse decodes a gatekeeper.yaml document from bytes and applies defaults.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Image == "" {
		return fmt.Errorf("config: image is required")
	}
	if len(c.Policies) == 0 {
		return fmt.Errorf("config: at least one policy profile is required")
	}
	if _, ok := c.Policies["default"]; !ok {
		return fmt.Errorf("config: a %q policy profile is required", "default")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Policies == nil {
		c.Policies = map[string]Profile{}
	}
}

// ResolvedProfile is a profile with all inheritance flattened and every toggle
// resolved to a concrete boolean.
type ResolvedProfile struct {
	Name                        string
	DenyNetworkOutsideAllowlist bool
	DenyWritesOutsideWorkspace  bool
	SecretScan                  bool
	BlockPublicS3               bool
	FailOnWarn                  bool
}

// SelectProfileName picks the profile name for a PR: the "agent" profile when
// the author is a bot or the branch matches an agent pattern (and that profile
// exists), otherwise "default".
func (c *Config) SelectProfileName(isAgent bool) string {
	if isAgent {
		if _, ok := c.Policies["agent"]; ok {
			return "agent"
		}
	}
	return "default"
}

// Resolve flattens a profile by name, following the Inherit chain. It is safe
// against cycles.
func (c *Config) Resolve(name string) (ResolvedProfile, error) {
	merged, err := c.mergeChain(name, map[string]bool{})
	if err != nil {
		return ResolvedProfile{}, err
	}
	rp := ResolvedProfile{Name: name}
	if merged.DenyNetworkOutsideAllowlist != nil {
		rp.DenyNetworkOutsideAllowlist = *merged.DenyNetworkOutsideAllowlist
	}
	if merged.DenyWritesOutsideWorkspace != nil {
		rp.DenyWritesOutsideWorkspace = *merged.DenyWritesOutsideWorkspace
	}
	if merged.SecretScan != nil {
		rp.SecretScan = *merged.SecretScan
	}
	if merged.IaC != nil && merged.IaC.BlockPublicS3 != nil {
		rp.BlockPublicS3 = *merged.IaC.BlockPublicS3
	}
	for _, f := range merged.FailOn {
		if f == "warn" {
			rp.FailOnWarn = true
		}
	}
	return rp, nil
}

// mergeChain resolves inheritance by starting from the base profile and
// overlaying the requested profile on top, so child values win.
func (c *Config) mergeChain(name string, seen map[string]bool) (Profile, error) {
	if seen[name] {
		return Profile{}, fmt.Errorf("config: inheritance cycle at profile %q", name)
	}
	seen[name] = true

	p, ok := c.Policies[name]
	if !ok {
		return Profile{}, fmt.Errorf("config: unknown profile %q", name)
	}
	if p.Inherit == "" {
		return p, nil
	}
	base, err := c.mergeChain(p.Inherit, seen)
	if err != nil {
		return Profile{}, err
	}
	return overlay(base, p), nil
}

// overlay returns base with any set fields from child taking precedence.
func overlay(base, child Profile) Profile {
	out := base
	out.Inherit = ""
	if child.DenyNetworkOutsideAllowlist != nil {
		out.DenyNetworkOutsideAllowlist = child.DenyNetworkOutsideAllowlist
	}
	if child.DenyWritesOutsideWorkspace != nil {
		out.DenyWritesOutsideWorkspace = child.DenyWritesOutsideWorkspace
	}
	if child.SecretScan != nil {
		out.SecretScan = child.SecretScan
	}
	if child.IaC != nil {
		if out.IaC == nil {
			out.IaC = &IaCRules{}
		}
		if child.IaC.BlockPublicS3 != nil {
			out.IaC.BlockPublicS3 = child.IaC.BlockPublicS3
		}
	}
	if len(child.FailOn) > 0 {
		out.FailOn = child.FailOn
	}
	return out
}
