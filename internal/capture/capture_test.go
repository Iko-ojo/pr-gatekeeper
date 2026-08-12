package capture

import (
	"strings"
	"testing"
)

func TestParseSquidLog(t *testing.T) {
	log := `1720000000.123 45 172.17.0.3 TCP_DENIED/403 3813 CONNECT evil.example:443 - HIER_NONE/- text/html
1720000001.500 12 172.17.0.3 TCP_TUNNEL/200 5000 CONNECT github.com:443 - ORIGINAL_DST/140.82.121.4 -
Squid startup: this line is not an access record and must be ignored`

	entries := ParseSquidLog(strings.NewReader(log))
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].Host != "evil.example" || entries[0].Allowed {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if entries[1].Host != "github.com" || !entries[1].Allowed {
		t.Errorf("entry 1 = %+v", entries[1])
	}
}

func TestEgressFindingsOnlyDenied(t *testing.T) {
	entries := []EgressEntry{
		{Host: "evil.example", Allowed: false},
		{Host: "evil.example", Allowed: false}, // duplicate, should dedupe
		{Host: "github.com", Allowed: true},
	}
	findings := EgressFindings(entries)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource != "evil.example" || findings[0].Rule != "egress.denied" {
		t.Errorf("finding = %+v", findings[0])
	}
}

func TestParseDockerDiff(t *testing.T) {
	diff := `A /workspace/newfile.txt
C /etc/passwd
A /usr/local/bin/backdoor
D /tmp/something
A /tmp/scratch
A /var/log/app.log`

	paths := ParseDockerDiff(strings.NewReader(diff), WorkspaceMount)
	// Expect /etc/passwd and /usr/local/bin/backdoor only.
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
}

func TestParseDockerDiffIgnoresHomeCaches(t *testing.T) {
	// npm/pip/go write caches under the build user's HOME on every run; these
	// must not be flagged, while genuine system tampering still is.
	diff := `C /root
A /root/.npm
A /root/.npm/_logs/2026-08-12T19_24_16_265Z-debug-0.log
A /root/.cache/go-build/ab/cdef
A /home/builder/.config/thing
C /etc/passwd`

	paths := ParseDockerDiff(strings.NewReader(diff), WorkspaceMount)
	if len(paths) != 1 || paths[0] != "/etc/passwd" {
		t.Fatalf("expected only /etc/passwd flagged, got %v", paths)
	}
}

func TestSecretScan(t *testing.T) {
	text := "harmless line\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nanother line"
	hits := ScanText("leak.env", text)
	if len(hits) == 0 {
		t.Fatal("expected at least one secret hit")
	}
	found := false
	for _, h := range hits {
		if h.Rule == "secret.aws_access_key" && h.Line == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("aws access key not detected at line 2: %+v", hits)
	}
}

func TestSecretScanCleanText(t *testing.T) {
	if hits := ScanText("clean", "just some normal code\nx := 1\n"); len(hits) != 0 {
		t.Errorf("expected no hits, got %+v", hits)
	}
}
