package operations

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicProjectionsOmitInternalIDs(t *testing.T) {
	payloads := []any{
		Organization{Name: "Acme", Slug: "acme"},
		Vulnerability{Slug: "vuln-abc", Title: "SQL injection", AssetResourceSlug: "ARES-AJ3"},
		Asset{Slug: "AR-9R4", KindName: "Repository", AssetType: "repository"},
		Identity{Slug: "OID-9C4", Name: "alice", Email: "alice@example.com", IdentityType: "human"},
		Detection{Slug: "DET-9C4", Title: "Suspicious login"},
		Scan{Slug: "SCAN-9RG", Status: "completed"},
		ScanDetail{Slug: "SCAN-9RG", AssetType: "repository", AssetName: "web-app"},
		VulnerabilitySnapshot{Slug: "vuln-new1", AssetType: "repository", AssetName: "web-app"},
		ScanScheduleResult{Message: "Scan scheduled", Slug: ptr("SCAN-202")},
		FixerExecuteResult{Status: "pending", DetailsURL: "/fix/9/"},
		Page[Vulnerability]{Results: []Vulnerability{{Slug: "vuln-abc"}}},
	}

	forbidden := []string{
		`"id":`,
		`"asset_id":`,
		`"assignee_id":`,
		`"scan_id":`,
		`"fix_id":`,
		`"attempt_id":`,
		`"root_resource_id":`,
		`"resource_id":`,
	}
	for _, payload := range payloads {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal %T: %v", payload, err)
		}
		encoded := string(raw)
		for _, key := range forbidden {
			if strings.Contains(encoded, key) {
				t.Errorf("%T JSON contains internal id %s: %s", payload, key, encoded)
			}
		}
	}
}

func ptr(s string) *string { return &s }
