package operations

import (
	"testing"
)

func TestRegisterEnumeratesOrganizationsList(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("expected at least one registered operation")
	}
	found := false
	for _, name := range names {
		if name == OrganizationsList.Name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("organizations.list missing from registry: %v", names)
	}
}

func TestListOperationsArePaginated(t *testing.T) {
	var listOps, paginatedOps []string
	for _, d := range All() {
		if IsListName(d.Name) {
			listOps = append(listOps, d.Name)
			if !d.Paginated {
				t.Errorf("list operation %q is missing PageInput", d.Name)
			}
		}
		if d.Paginated {
			paginatedOps = append(paginatedOps, d.Name)
			if !IsListName(d.Name) {
				t.Errorf("paginated operation %q is not named as a list operation", d.Name)
			}
		}
	}
	if len(listOps) == 0 {
		t.Fatal("expected at least one list operation")
	}
	if len(paginatedOps) != len(listOps) {
		t.Fatalf("paginated ops %v do not match list ops %v", paginatedOps, listOps)
	}
}

func TestSeverityCode(t *testing.T) {
	code, err := SeverityCode("critical")
	if err != nil || code != "0" {
		t.Fatalf("SeverityCode(critical) = %q, %v", code, err)
	}
	code, err = SeverityCode("3")
	if err != nil || code != "3" {
		t.Fatalf("SeverityCode(3) = %q, %v", code, err)
	}
	if _, err := SeverityCode("nope"); err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestOrganizationInputRequire(t *testing.T) {
	if _, err := (OrganizationInput{}).require(); err == nil {
		t.Fatal("expected missing organization error")
	}
	slug, err := (OrganizationInput{OrganizationSlug: "acme"}).require()
	if err != nil || slug != "acme" {
		t.Fatalf("require = %q, %v", slug, err)
	}
}
