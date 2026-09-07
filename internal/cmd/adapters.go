package cmd

import (
	"context"
	"fmt"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

const operationAnnotation = "fencer.operation"

func addMCPTool[Input, Output any](server *mcp.Server, client *api.Client, operation operations.Operation[Input, Output]) {
	destructive := operation.Safety == operations.SafetyDestructive
	mcp.AddTool(server, &mcp.Tool{
		Name:        operation.Name,
		Description: operation.Description,
		InputSchema: operations.InputJSONSchema[Input](),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    operation.Safety == operations.SafetyReadOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  operation.Idempotent,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, Output, error) {
		output, err := operation.Execute(ctx, client, input)
		return nil, output, err
	})
}

func addOrgMCPTool[Input, Output any](server *mcp.Server, client *api.Client, operation operations.Operation[Input, Output]) {
	destructive := operation.Safety == operations.SafetyDestructive
	mcp.AddTool(server, &mcp.Tool{
		Name:        operation.Name,
		Description: operation.Description,
		InputSchema: operations.InputJSONSchema[Input](),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    operation.Safety == operations.SafetyReadOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  operation.Idempotent,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, Output, error) {
		input, err := withResolvedOrg(input)
		if err != nil {
			var zero Output
			return nil, zero, err
		}
		output, err := operation.Execute(ctx, client, input)
		return nil, output, err
	})
}

func withResolvedOrg[I any](input I) (I, error) {
	v := reflect.ValueOf(&input).Elem()
	if v.Kind() != reflect.Struct {
		return input, fmt.Errorf("operation input must be a struct")
	}
	f := v.FieldByName("OrganizationSlug")
	if !f.IsValid() || f.Kind() != reflect.String {
		return input, fmt.Errorf("operation input is missing OrganizationSlug")
	}
	if f.String() != "" {
		return input, nil
	}
	slug, err := resolveOrgSlug()
	if err != nil {
		return input, err
	}
	if !f.CanSet() {
		return input, fmt.Errorf("operation input OrganizationSlug cannot be set")
	}
	f.SetString(slug)
	return input, nil
}
