package cmd

import "testing"

type orgScopedInput struct {
	OrganizationSlug string
	Other            string
}

func TestWithResolvedOrgUsesExplicitSlug(t *testing.T) {
	setupActionTest(t)
	got, err := withResolvedOrg(nil, orgScopedInput{OrganizationSlug: "acme", Other: "x"})
	if err != nil {
		t.Fatalf("withResolvedOrg: %v", err)
	}
	if got.OrganizationSlug != "acme" || got.Other != "x" {
		t.Fatalf("unexpected input: %+v", got)
	}
}

func TestWithResolvedOrgFallsBackToOrgFlag(t *testing.T) {
	setupActionTest(t)
	orgSlug = "from-flag"
	got, err := withResolvedOrg(nil, orgScopedInput{})
	if err != nil {
		t.Fatalf("withResolvedOrg: %v", err)
	}
	if got.OrganizationSlug != "from-flag" {
		t.Fatalf("OrganizationSlug = %q, want from-flag", got.OrganizationSlug)
	}
}

func TestWithResolvedOrgMissing(t *testing.T) {
	setupActionTest(t)
	_, err := withResolvedOrg(nil, orgScopedInput{})
	if err == nil {
		t.Fatal("expected missing organization error")
	}
}
