package operations

import (
	"reflect"
	"strings"
	"testing"

	"fencer/cli/api/schema"
)

func TestValidateIgnoreReasonAcceptsSchemaValues(t *testing.T) {
	t.Parallel()
	for _, reason := range []schema.IgnoredReasonEnum{
		schema.IgnoredReasonEnumAcceptableRisk,
		schema.IgnoredReasonEnumDuplicate,
		schema.IgnoredReasonEnumFalsePositive,
		schema.IgnoredReasonEnumNoFixAvailable,
		schema.IgnoredReasonEnumRuleDisabled,
		schema.IgnoredReasonEnumSuperseded,
		schema.IgnoredReasonEnumThirdPartyCode,
		schema.IgnoredReasonEnumWillNotFix,
	} {
		if err := ValidateIgnoreReason(string(reason)); err != nil {
			t.Fatalf("schema reason %q should be valid: %v", reason, err)
		}
	}
}

func TestValidateIgnoreReasonRejectsUnknown(t *testing.T) {
	t.Parallel()
	if err := ValidateIgnoreReason("not-a-reason"); err == nil {
		t.Fatal("expected unknown ignore reason to fail")
	}
}

func TestIgnoreReasonHelpListsEverySchemaValue(t *testing.T) {
	t.Parallel()
	help := IgnoreReasonHelp()
	for _, reason := range []string{
		string(schema.IgnoredReasonEnumAcceptableRisk),
		string(schema.IgnoredReasonEnumDuplicate),
		string(schema.IgnoredReasonEnumFalsePositive),
		string(schema.IgnoredReasonEnumNoFixAvailable),
		string(schema.IgnoredReasonEnumRuleDisabled),
		string(schema.IgnoredReasonEnumSuperseded),
		string(schema.IgnoredReasonEnumThirdPartyCode),
		string(schema.IgnoredReasonEnumWillNotFix),
	} {
		if !strings.Contains(help, reason) {
			t.Fatalf("help %q missing schema value %q", help, reason)
		}
	}
}

func TestValidateDeferDaysAcceptsSchemaValues(t *testing.T) {
	t.Parallel()
	for _, days := range []schema.DeferDaysEnum{schema.N7, schema.N14, schema.N30, schema.N90} {
		if err := ValidateDeferDays(int(days)); err != nil {
			t.Fatalf("schema days %d should be valid: %v", days, err)
		}
	}
}

func TestValidatePriorityLevelAcceptsSchemaValues(t *testing.T) {
	t.Parallel()
	for _, level := range []schema.PriorityLevelEnum{
		schema.PriorityLevelEnumUrgent,
		schema.PriorityLevelEnumHigh,
		schema.PriorityLevelEnumModerate,
		schema.PriorityLevelEnumLow,
		schema.PriorityLevelEnumMinimal,
	} {
		if err := ValidatePriorityLevel(string(level)); err != nil {
			t.Fatalf("schema priority %q should be valid: %v", level, err)
		}
	}
}

func TestValidateOrderByAcceptsVulnerabilitySchemaValues(t *testing.T) {
	t.Parallel()
	if err := ValidateOrderBy[schema.VulnerabilitiesListParamsOrderBy](string(schema.VulnerabilitiesListParamsOrderByFirstSeen)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOrderBy[schema.VulnerabilitiesListParamsOrderBy](string(schema.VulnerabilitiesListParamsOrderByMinusFirstSeen)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOrderBy[schema.VulnerabilitiesListParamsOrderBy]("created_at"); err == nil {
		t.Fatal("created_at is not a vulnerabilities order_by value")
	}
}

func TestListOrderByHelpMatchesSchema(t *testing.T) {
	t.Parallel()
	cases := []struct {
		help   string
		values []string
	}{
		{VulnerabilityOrderByHelp, []string{"first_seen", "sla_deadline", "id"}},
		{DetectionOrderByHelp, []string{"detected_at", "assignee_name", "confidence_label"}},
		{AssetOrderByHelp, []string{"kind", "provider", "description"}},
		{IdentityOrderByHelp, []string{"display_name", "primary_email", "last_seen_at"}},
		{ScanVulnerabilityOrderByHelp, []string{"severity", "first_seen", "asset_name"}},
	}
	for _, tc := range cases {
		for _, value := range tc.values {
			if !strings.Contains(tc.help, value) {
				t.Fatalf("help %q missing %q", tc.help, value)
			}
		}
	}
}

func TestJSONSchemaTypesUseGeneratedEnums(t *testing.T) {
	t.Parallel()
	schemas := JSONSchemaTypes()
	orderBy := schemas[reflect.TypeFor[schema.IdentitiesListParamsOrderBy]()]
	if orderBy == nil {
		t.Fatal("missing identities order_by schema")
	}
	if !strings.Contains(orderBy.Description, IdentityOrderByHelp) {
		t.Fatalf("description %q missing help %q", orderBy.Description, IdentityOrderByHelp)
	}
	if len(orderBy.Enum) != len(identityOrderBy) {
		t.Fatalf("identities order_by enum len %d, generated consts %d", len(orderBy.Enum), len(identityOrderBy))
	}
	if !enumContains(orderBy.Enum, string(schema.IdentitiesListParamsOrderByLastSeenAt)) {
		t.Fatalf("enum %#v missing last_seen_at", orderBy.Enum)
	}
	if !enumContains(orderBy.Enum, string(schema.IdentitiesListParamsOrderByMinusLastSeenAt)) {
		t.Fatalf("enum %#v missing -last_seen_at", orderBy.Enum)
	}

	detections := schemas[reflect.TypeFor[schema.DetectionsListParamsOrderBy]()]
	if !enumContains(detections.Enum, string(schema.DetectionsListParamsOrderByDetectedAt)) {
		t.Fatalf("enum %#v missing detected_at", detections.Enum)
	}
	if !enumContains(detections.Enum, string(schema.DetectionsListParamsOrderByMinusDetectedAt)) {
		t.Fatalf("enum %#v missing -detected_at", detections.Enum)
	}

	reason := schemas[reflect.TypeFor[schema.IgnoredReasonEnum]()]
	if !enumContains(reason.Enum, string(schema.IgnoredReasonEnumNoFixAvailable)) {
		t.Fatalf("reason enum %#v missing no_fix_available", reason.Enum)
	}

	days := schemas[reflect.TypeFor[schema.DeferDaysEnum]()]
	if !enumContains(days.Enum, int(schema.N14)) {
		t.Fatalf("days enum %#v missing 14", days.Enum)
	}

	category := schemas[reflect.TypeFor[schema.VulnerabilitiesListParamsCategory]()]
	if !enumContains(category.Enum, string(schema.VulnerabilitiesListParamsCategoryAiAgent)) {
		t.Fatalf("category enum %#v missing ai-agent", category.Enum)
	}
}

func TestOrderByFieldsDoNotHardcodeJSONSchemaEnums(t *testing.T) {
	t.Parallel()
	inputs := []any{
		VulnerabilitiesListInput{},
		DetectionsListInput{},
		AssetsListInput{},
		IdentitiesListInput{},
		ScansListVulnerabilitiesInput{},
	}
	for _, input := range inputs {
		typ := reflect.TypeOf(input)
		field, ok := typ.FieldByName("OrderBy")
		if !ok {
			t.Fatalf("%s missing OrderBy", typ.Name())
		}
		if field.Type.Kind() == reflect.String && field.Type.Name() == "string" {
			t.Errorf("%s.OrderBy is an untyped string", typ.Name())
		}
		if strings.Contains(field.Tag.Get("jsonschema"), "|") {
			t.Errorf("%s.OrderBy jsonschema tag hardcodes enums: %q", typ.Name(), field.Tag.Get("jsonschema"))
		}
	}

	category, _ := reflect.TypeOf(VulnerabilitiesListInput{}).FieldByName("Category")
	if strings.Contains(category.Tag.Get("jsonschema"), "|") {
		t.Fatalf("category jsonschema tag hardcodes enums: %q", category.Tag.Get("jsonschema"))
	}
	priority, _ := reflect.TypeOf(VulnerabilitiesListInput{}).FieldByName("PriorityLevel")
	if strings.Contains(priority.Tag.Get("jsonschema"), "|") {
		t.Fatalf("priority_level jsonschema tag hardcodes enums: %q", priority.Tag.Get("jsonschema"))
	}
}

func enumContains(enum []any, want any) bool {
	for _, v := range enum {
		if v == want {
			return true
		}
	}
	return false
}
