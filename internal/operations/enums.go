package operations

import (
	"fmt"
	"strings"

	"fencer/cli/api/schema"
)

type (
	VulnerabilityOrderBy      = schema.VulnerabilitiesListParamsOrderBy
	DetectionOrderBy          = schema.DetectionsListParamsOrderBy
	AssetOrderBy              = schema.AssetInventoryListParamsOrderBy
	IdentityOrderBy           = schema.IdentitiesListParamsOrderBy
	ScanVulnerabilityOrderBy  = schema.ScanVulnerabilitySnapshotsListParamsOrderBy
	IgnoredReason             = schema.IgnoredReasonEnum
	DeferDays                 = schema.DeferDaysEnum
	PriorityLevel             = schema.PriorityLevelEnum
	VulnerabilityCategory     = schema.VulnerabilitiesListParamsCategory
	ScanVulnerabilityCategory = schema.ScanVulnerabilitySnapshotsListParamsCategory
)

var (
	VulnerabilityOrderByHelp      = joinUnique(vulnerabilityOrderBy...)
	DetectionOrderByHelp          = joinUnique(detectionOrderBy...)
	AssetOrderByHelp              = joinUnique(assetOrderBy...)
	IdentityOrderByHelp           = joinUnique(identityOrderBy...)
	ScanVulnerabilityOrderByHelp  = joinUnique(scanVulnerabilityOrderBy...)
	VulnerabilityCategoryHelp     = joinUnique(vulnerabilityCategory...)
	ScanVulnerabilityCategoryHelp = joinUnique(scanVulnerabilityCategory...)
)

func joinUnique[E ~string](values ...E) string {
	seen := map[string]struct{}{}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		s := strings.TrimPrefix(string(v), "-")
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		parts = append(parts, s)
	}
	return strings.Join(parts, "|")
}

func IgnoreReasonHelp() string {
	return joinUnique(ignoreReasons...)
}

func DeferDaysHelp() string {
	parts := make([]string, len(deferDays))
	for i, d := range deferDays {
		parts[i] = fmt.Sprintf("%d", int(d))
	}
	return strings.Join(parts, "|")
}

func PriorityLevelHelp() string {
	return joinUnique(priorityLevels...)
}

func MapStrings[E ~string](values []string) []E {
	out := make([]E, len(values))
	for i, v := range values {
		out[i] = E(v)
	}
	return out
}

func ValidateIgnoreReason(reason string) error {
	if reason == "" {
		return nil
	}
	if !schema.IgnoredReasonEnum(reason).Valid() {
		return fmt.Errorf("invalid reason %q", reason)
	}
	return nil
}

func ValidateDeferDays(days int) error {
	if !schema.DeferDaysEnum(days).Valid() {
		return fmt.Errorf("days must be one of %s", DeferDaysHelp())
	}
	return nil
}

func ValidatePriorityLevel(level string) error {
	if !schema.PriorityLevelEnum(level).Valid() {
		return fmt.Errorf("level must be one of %s", strings.ReplaceAll(PriorityLevelHelp(), "|", ", "))
	}
	return nil
}

func ValidateEnum[E interface {
	~string
	Valid() bool
}](value string) error {
	if value == "" {
		return nil
	}
	if !E(value).Valid() {
		return fmt.Errorf("invalid value %q", value)
	}
	return nil
}

func ValidateOrderBy[E interface {
	~string
	Valid() bool
}](value string) error {
	return ValidateEnum[E](value)
}

func mustValid[E interface {
	~string
	Valid() bool
}](values []E) {
	for _, v := range values {
		if !v.Valid() {
			panic(fmt.Sprintf("schema enum value %q is not valid", v))
		}
	}
}

func init() {
	mustValid(ignoreReasons)
	mustValid(priorityLevels)
	mustValid(vulnerabilityOrderBy)
	mustValid(detectionOrderBy)
	mustValid(assetOrderBy)
	mustValid(identityOrderBy)
	mustValid(scanVulnerabilityOrderBy)
	mustValid(vulnerabilityCategory)
	mustValid(scanVulnerabilityCategory)
	for _, days := range deferDays {
		if !days.Valid() {
			panic(fmt.Sprintf("schema defer days %d is not valid", days))
		}
	}
}
