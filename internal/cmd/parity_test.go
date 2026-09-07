package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"fencer/cli/internal/operations"
)

var localOnlyCommandExemptions = map[string]bool{
	"login":   true,
	"logout":  true,
	"org use": true,
	"mcp":     true,
	"version": true,
}

var pendingCLIMigrations = map[string]string{}

var pendingLegacyMCPTools = map[string]bool{}

var extraMCPTools = map[string]bool{}

func TestCLIAndMCPOperationParity(t *testing.T) {
	setupActionTest(t)

	registered := map[string]bool{}
	for _, name := range operations.Names() {
		if registered[name] {
			t.Errorf("duplicate registered operation %q", name)
		}
		registered[name] = true
	}

	leaves := leafCommandPaths(rootCmd)
	seenPending := map[string]bool{}
	for _, path := range leaves {
		if localOnlyCommandExemptions[path] || isHelpOrCompletion(path) {
			continue
		}
		cmd := commandByPath(rootCmd, path)
		if cmd == nil {
			t.Fatalf("missing command for path %q", path)
		}
		annotation := cmd.Annotations[operationAnnotation]
		pendingOp, pending := pendingCLIMigrations[path]
		switch {
		case pending && annotation != "":
			t.Errorf("command %q is listed as pending but already references %q; remove it from pendingCLIMigrations", path, annotation)
		case pending:
			seenPending[path] = true
		case annotation == "":
			t.Errorf("API-backed command %q has no %s annotation and is not listed as pending or exempt", path, operationAnnotation)
		case !registered[annotation]:
			t.Errorf("command %q references unregistered operation %q", path, annotation)
		}
		if pending && pendingOp == "" {
			t.Errorf("pending command %q is missing its target operation name", path)
		}
	}
	for path := range pendingCLIMigrations {
		if !seenPending[path] {
			t.Errorf("pendingCLIMigrations contains unknown or non-leaf command %q", path)
		}
	}

	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })
	listed, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	mcpNames := map[string]bool{}
	for _, tool := range listed.Tools {
		mcpNames[tool.Name] = true
		switch {
		case registered[tool.Name]:
		case pendingLegacyMCPTools[tool.Name]:
		case extraMCPTools[tool.Name]:
		default:
			t.Errorf("MCP tool %q is not a registered operation, pending legacy handler, or documented extra tool", tool.Name)
		}
	}
	for _, name := range operations.Names() {
		if !mcpNames[name] {
			t.Errorf("registered operation %q is not exposed as an MCP tool", name)
		}
	}
	for name := range pendingLegacyMCPTools {
		if registered[name] {
			t.Errorf("pending legacy MCP tool %q is already registered; remove it from pendingLegacyMCPTools", name)
		}
		if !mcpNames[name] {
			t.Errorf("pending legacy MCP tool %q is not registered on the server", name)
		}
	}
	for name := range extraMCPTools {
		if !mcpNames[name] {
			t.Errorf("documented extra MCP tool %q is not registered on the server", name)
		}
	}
}

func TestListOperationsHaveCLIPaginationFlagsAndMCPSchemas(t *testing.T) {
	setupActionTest(t)

	annotated := map[string]*cobra.Command{}
	for _, path := range leafCommandPaths(rootCmd) {
		cmd := commandByPath(rootCmd, path)
		if cmd == nil {
			continue
		}
		name := cmd.Annotations[operationAnnotation]
		if name != "" {
			annotated[name] = cmd
		}
	}

	cs, _ := newMCPSession(t, func(*http.Request) (int, string) { return 200, okListJSON })
	listed, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	mcpTools := map[string]*mcp.Tool{}
	for _, tool := range listed.Tools {
		mcpTools[tool.Name] = tool
	}

	var listCount int
	for _, d := range operations.All() {
		if !d.Paginated {
			if operations.IsListName(d.Name) {
				t.Errorf("list operation %q is not marked paginated", d.Name)
			}
			continue
		}
		listCount++
		cmd := annotated[d.Name]
		if cmd == nil {
			t.Errorf("paginated operation %q has no CLI command", d.Name)
		} else {
			if cmd.Flags().Lookup("page") == nil {
				t.Errorf("command for %q is missing --page", d.Name)
			}
			if cmd.Flags().Lookup("page-size") == nil {
				t.Errorf("command for %q is missing --page-size", d.Name)
			}
		}
		tool, ok := mcpTools[d.Name]
		if !ok {
			t.Errorf("paginated operation %q is not an MCP tool", d.Name)
			continue
		}
		input, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal input schema for %s: %v", d.Name, err)
		}
		output, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal output schema for %s: %v", d.Name, err)
		}
		for _, field := range []string{"page", "page_size"} {
			if !strings.Contains(string(input), `"`+field+`"`) {
				t.Errorf("%s input schema missing %q: %s", d.Name, field, input)
			}
		}
		for _, field := range []string{"results", "pagination"} {
			if !strings.Contains(string(output), `"`+field+`"`) {
				t.Errorf("%s output schema missing %q: %s", d.Name, field, output)
			}
		}
	}
	if listCount == 0 {
		t.Fatal("expected at least one paginated list operation")
	}
}

func TestLocalOnlyCommandsStayUnannotated(t *testing.T) {
	for path := range localOnlyCommandExemptions {
		cmd := commandByPath(rootCmd, path)
		if cmd == nil {
			t.Errorf("exemption %q does not match a command", path)
			continue
		}
		if cmd.Annotations[operationAnnotation] != "" {
			t.Errorf("local-only command %q must not reference a Fencer operation", path)
		}
	}
}

func leafCommandPaths(cmd *cobra.Command) []string {
	var paths []string
	for _, child := range cmd.Commands() {
		if child.Hidden {
			continue
		}
		path := commandPath(child)
		if child.HasSubCommands() {
			paths = append(paths, leafCommandPaths(child)...)
			continue
		}
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

func commandPath(cmd *cobra.Command) string {
	parts := strings.Fields(cmd.CommandPath())
	if len(parts) > 0 && parts[0] == rootCmd.Name() {
		parts = parts[1:]
	}
	return strings.Join(parts, " ")
}

func commandByPath(cmd *cobra.Command, path string) *cobra.Command {
	if path == "" {
		return cmd
	}
	current := cmd
	for _, name := range strings.Fields(path) {
		var next *cobra.Command
		for _, child := range current.Commands() {
			if child.Name() == name {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}
		current = next
	}
	return current
}

func isHelpOrCompletion(path string) bool {
	return path == "help" || path == "completion" || strings.HasPrefix(path, "completion ")
}
