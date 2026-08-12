# Agent PR Gatekeeper

A CI-native pre-merge platform that answers one question per pull request:

> **Did this change behave safely when executed, and does it violate org policy?**

Unlike static-only scanners, the gatekeeper runs the PR's lifecycle commands
inside a **network-restricted Docker sandbox**, captures what the code
**actually did** (egress attempts, out-of-workspace writes, leaked secrets),
adds diff-scoped IaC checks, evaluates everything against **policy-as-code**,
and posts a **merge verdict with evidence** as a GitHub Check Run and PR
comment.

It is **agent-aware**: pull requests opened by bots or on `agent/*` branches get
a stricter policy profile.

## How it works

```
PR event -> gatekeeper run
  1. Load gatekeeper.yaml, pick policy profile (default vs agent)
  2. Sandbox: run build/test in a container whose only egress route is an
     allow-list proxy; capture denied hosts + filesystem diff + output
  3. Static: secret scan + IaC checks over changed files
  4. Policy: filter/grade findings -> verdict (pass | warn | block)
  5. Report: JSON evidence bundle + Markdown
  6. Publish: GitHub Check Run + PR comment; exit code gates the merge
```

The workload container joins only an `--internal` Docker network, so it cannot
reach the internet except through the Squid proxy, which enforces the
allow-list and logs every attempt.

## Configuration (`gatekeeper.yaml`)

```yaml
image: node:20
commands:
  build: npm ci
  test: npm test
network:
  allow: [github.com, registry.npmjs.org]   # everything else is denied + logged
policies:
  default:
    deny_network_outside_allowlist: true
    deny_writes_outside_workspace: true
    secret_scan: true
    iac:
      block_public_s3: true
  agent:
    inherit: default
    fail_on: [warn]                          # stricter: warnings block the merge
```

Generate a starter file with `gatekeeper init`.

## Usage

### As a GitHub Action

See [.github/workflows/gatekeeper.yml](.github/workflows/gatekeeper.yml):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: Iko-ojo/pr-gatekeeper@v1
  with:
    config: gatekeeper.yaml
    workspace: .
    base-ref: ${{ github.base_ref }}
```

### Locally

```bash
go build -o gatekeeper ./cmd/gatekeeper
./gatekeeper init
./gatekeeper run --workspace . --no-publish      # prints the Markdown verdict
```

`run` exits non-zero only when the decision is `block`, so it can gate a merge
directly.

## CLI

| Command | Purpose |
| --- | --- |
| `gatekeeper run` | Evaluate the current PR and post a verdict |
| `gatekeeper init` | Write a starter `gatekeeper.yaml` |
| `gatekeeper version` | Print the version |

Key `run` flags: `--config`, `--workspace`, `--base-ref`, `--output-dir`,
`--agent` (force the agent profile), `--no-sandbox` (static-only),
`--no-publish`.

## Project layout

```
cmd/gatekeeper/     CLI entrypoint (run/init/version)
internal/config/    gatekeeper.yaml schema, loader, profile resolution
internal/sandbox/   Docker runner: egress proxy + workload container
internal/capture/   egress log parsing, docker diff, secret scanning
internal/static/    diff-scoped IaC analysis (built-in + tfsec adapter)
internal/policy/    policy engine + verdict computation
internal/report/    Markdown + JSON evidence bundle
internal/github/    Check Run + PR comment client
examples/node-app/  demo target repo with a deliberately unsafe fixture
```

## Scope

**Implemented:** Docker sandbox with egress allow-list, out-of-workspace write
detection, regex secret scanning, built-in public-S3 IaC check plus optional
tfsec, YAML policy engine, GitHub Check Run + comment, evidence bundle.

**Deferred (v2):** Firecracker/gVisor backend, OPA/Rego policies, syscall-level
audit (eBPF), agent attestation (declared vs actual behaviour), GitHub App for
org-wide install, GitLab adapter.

## Development

```bash
go build ./...
go test ./...
```

Docker is required only for the sandbox at runtime; the CLI degrades to a
static-only run when Docker is unavailable.
