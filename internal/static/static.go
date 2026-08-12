// Package static performs diff-scoped static analysis of a PR. It combines a
// deterministic built-in check (public S3 buckets) with optional external
// scanners (tfsec) when those binaries are available on PATH.
package static

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Iko-ojo/pr-gatekeeper/internal/model"
)

// Analyzer runs static checks over a working directory.
type Analyzer struct {
	// Dir is the workspace root to analyse.
	Dir string
	// runner executes external scanners; injectable for tests.
	runner commandRunner
	// readFile reads a file's contents; injectable for tests.
	readFile func(string) ([]byte, error)
	// lookPath resolves a binary on PATH; injectable for tests.
	lookPath func(string) (string, error)
}

type commandRunner func(name string, args ...string) ([]byte, error)

// NewAnalyzer builds an Analyzer that shells out to real scanners.
func NewAnalyzer(dir string) *Analyzer {
	return &Analyzer{
		Dir: dir,
		runner: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).Output()
		},
		readFile: os.ReadFile,
		lookPath: exec.LookPath,
	}
}

// Analyze returns findings for the given changed files. Only files that look
// like infrastructure-as-code are considered.
func (a *Analyzer) Analyze(changedFiles []string) []model.Finding {
	var findings []model.Finding

	tfFiles := filterByExt(changedFiles, ".tf")
	for _, f := range tfFiles {
		findings = append(findings, a.builtinPublicS3(f)...)
	}

	if len(tfFiles) > 0 && a.lookPath != nil {
		if _, err := a.lookPath("tfsec"); err == nil {
			findings = append(findings, a.runTfsec()...)
		}
	}
	return findings
}

// builtinPublicS3 flags a Terraform file that makes an S3 bucket publicly
// readable/writable, either via a legacy ACL or a public_access_block that
// disables the protections.
func (a *Analyzer) builtinPublicS3(relPath string) []model.Finding {
	full := filepath.Join(a.Dir, relPath)
	content, err := a.readFile(full)
	if err != nil {
		return nil
	}
	lower := strings.ToLower(string(content))

	var findings []model.Finding
	if strings.Contains(lower, "acl") &&
		(strings.Contains(lower, `"public-read"`) || strings.Contains(lower, `"public-read-write"`)) {
		findings = append(findings, model.Finding{
			Category: model.CategoryIaC,
			Rule:     "iac.public_s3",
			Severity: model.SeverityBlock,
			Message:  "Terraform declares a public-read S3 ACL",
			Resource: relPath,
		})
	}
	if strings.Contains(lower, "aws_s3_bucket_public_access_block") &&
		strings.Contains(lower, "block_public_acls") &&
		strings.Contains(lower, "false") {
		findings = append(findings, model.Finding{
			Category: model.CategoryIaC,
			Rule:     "iac.public_s3",
			Severity: model.SeverityBlock,
			Message:  "Terraform disables S3 public access block protections",
			Resource: relPath,
		})
	}
	return findings
}

func filterByExt(files []string, ext string) []string {
	var out []string
	for _, f := range files {
		if strings.EqualFold(filepath.Ext(f), ext) {
			out = append(out, f)
		}
	}
	return out
}
