package static

import (
	"testing"

	"github.com/Iko-ojo/pr-gatekeeper/internal/model"
)

func newTestAnalyzer(files map[string]string) *Analyzer {
	return &Analyzer{
		Dir: "/repo",
		readFile: func(path string) ([]byte, error) {
			if c, ok := files[path]; ok {
				return []byte(c), nil
			}
			return nil, errNotFound
		},
		// No lookPath so external scanners are never invoked in tests.
		lookPath: nil,
	}
}

var errNotFound = &fileError{"not found"}

type fileError struct{ s string }

func (e *fileError) Error() string { return e.s }

func TestPublicS3ACLFlagged(t *testing.T) {
	a := newTestAnalyzer(map[string]string{
		"/repo/main.tf": `resource "aws_s3_bucket_acl" "x" { acl = "public-read" }`,
	})
	findings := a.Analyze([]string{"main.tf"})
	if !hasRule(findings, "iac.public_s3") {
		t.Fatalf("expected iac.public_s3 finding, got %+v", findings)
	}
}

func TestPrivateTerraformClean(t *testing.T) {
	a := newTestAnalyzer(map[string]string{
		"/repo/main.tf": `resource "aws_s3_bucket_acl" "x" { acl = "private" }`,
	})
	if findings := a.Analyze([]string{"main.tf"}); len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestNonTerraformIgnored(t *testing.T) {
	a := newTestAnalyzer(map[string]string{
		"/repo/app.js": `const acl = "public-read"`,
	})
	if findings := a.Analyze([]string{"app.js"}); len(findings) != 0 {
		t.Fatalf("expected non-tf files ignored, got %+v", findings)
	}
}

func hasRule(findings []model.Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
