package operations

import (
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"

	"fencer/cli/api/schema"
)

func JSONSchemaTypes() map[reflect.Type]*jsonschema.Schema {
	return map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[schema.VulnerabilitiesListParamsOrderBy]():             orderBySchema(VulnerabilityOrderByHelp, vulnerabilityOrderBy...),
		reflect.TypeFor[schema.DetectionsListParamsOrderBy]():                  orderBySchema(DetectionOrderByHelp, detectionOrderBy...),
		reflect.TypeFor[schema.AssetInventoryListParamsOrderBy]():              orderBySchema(AssetOrderByHelp, assetOrderBy...),
		reflect.TypeFor[schema.IdentitiesListParamsOrderBy]():                  orderBySchema(IdentityOrderByHelp, identityOrderBy...),
		reflect.TypeFor[schema.ScanVulnerabilitySnapshotsListParamsOrderBy]():  orderBySchema(ScanVulnerabilityOrderByHelp, scanVulnerabilityOrderBy...),
		reflect.TypeFor[schema.IgnoredReasonEnum]():                            stringEnumSchema("reason: "+IgnoreReasonHelp(), ignoreReasons...),
		reflect.TypeFor[schema.PriorityLevelEnum]():                            stringEnumSchema("priority level: "+PriorityLevelHelp(), priorityLevels...),
		reflect.TypeFor[schema.DeferDaysEnum]():                                intEnumSchema("defer duration in days: "+DeferDaysHelp(), deferDays...),
		reflect.TypeFor[schema.VulnerabilitiesListParamsCategory]():            stringEnumSchema("filter by category: "+VulnerabilityCategoryHelp, vulnerabilityCategory...),
		reflect.TypeFor[schema.ScanVulnerabilitySnapshotsListParamsCategory](): stringEnumSchema("filter by category: "+ScanVulnerabilityCategoryHelp, scanVulnerabilityCategory...),
	}
}

func InputJSONSchema[T any]() *jsonschema.Schema {
	s, err := jsonschema.For[T](&jsonschema.ForOptions{TypeSchemas: JSONSchemaTypes()})
	if err != nil {
		panic(err)
	}
	return s
}

func orderBySchema[E ~string](help string, values ...E) *jsonschema.Schema {
	return stringEnumSchema("sort field: "+help+"; prefix '-' for descending", values...)
}

func stringEnumSchema[E ~string](description string, values ...E) *jsonschema.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = string(v)
	}
	return &jsonschema.Schema{Type: "string", Description: description, Enum: enum}
}

func intEnumSchema[E ~int](description string, values ...E) *jsonschema.Schema {
	enum := make([]any, len(values))
	for i, v := range values {
		enum[i] = int(v)
	}
	return &jsonschema.Schema{Type: "integer", Description: description, Enum: enum}
}
