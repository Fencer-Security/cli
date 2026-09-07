package cmd

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"fencer/cli/internal/version"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run a Model Context Protocol (MCP) server over stdio",
	Long: `Run an MCP server over stdio, exposing Fencer operations as tools.

The server reuses the same authenticated session as the rest of the CLI — run
'fencer login' first. Point an MCP client (e.g. Claude Desktop) at the binary:

  {
    "mcpServers": {
      "fencer": { "command": "fencer", "args": ["mcp"], "env": { "FENCER_ORG": "<slug>" } }
    }
  }

Each org-scoped tool accepts an optional 'organization_slug'; when omitted it
falls back to --org / FENCER_ORG. Write tools include MCP safety annotations;
the CLI still prompts for confirmation unless --yes is passed.`,
	Args: cobra.NoArgs,
	RunE: runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMCP(cmd *cobra.Command, _ []string) error {
	client, err := newAPIClient()
	if err != nil {
		return err
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "fencer", Version: version.Version}, nil)
	registerMCPTools(server, client)

	return server.Run(cmd.Context(), &mcp.StdioTransport{})
}
