package cmd

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

func registerMCPTools(server *mcp.Server, client *api.Client) {
	addMCPTool(server, client, operations.OrganizationsList)
	addOrgMCPTool(server, client, operations.VulnerabilitiesList)
	addOrgMCPTool(server, client, operations.VulnerabilitiesGet)
	addOrgMCPTool(server, client, operations.VulnerabilitiesAssign)
	addOrgMCPTool(server, client, operations.VulnerabilitiesUnassign)
	addOrgMCPTool(server, client, operations.VulnerabilitiesIgnore)
	addOrgMCPTool(server, client, operations.VulnerabilitiesUnignore)
	addOrgMCPTool(server, client, operations.VulnerabilitiesDefer)
	addOrgMCPTool(server, client, operations.VulnerabilitiesUndefer)
	addOrgMCPTool(server, client, operations.VulnerabilitiesSetPriority)
	addOrgMCPTool(server, client, operations.VulnerabilitiesFix)
	addOrgMCPTool(server, client, operations.DetectionsList)
	addOrgMCPTool(server, client, operations.DetectionsGet)
	addOrgMCPTool(server, client, operations.DetectionsAssign)
	addOrgMCPTool(server, client, operations.DetectionsUnassign)
	addOrgMCPTool(server, client, operations.DetectionsInvestigate)
	addOrgMCPTool(server, client, operations.DetectionsResolve)
	addOrgMCPTool(server, client, operations.DetectionsReopen)
	addOrgMCPTool(server, client, operations.AssetsList)
	addOrgMCPTool(server, client, operations.AssetsGet)
	addOrgMCPTool(server, client, operations.AssetsFilters)
	addOrgMCPTool(server, client, operations.AssetsSetCriticality)
	addOrgMCPTool(server, client, operations.ScansList)
	addOrgMCPTool(server, client, operations.ScansGet)
	addOrgMCPTool(server, client, operations.ScansListVulnerabilities)
	addOrgMCPTool(server, client, operations.ScansDiff)
	addOrgMCPTool(server, client, operations.ScansSchedule)
	addOrgMCPTool(server, client, operations.IdentitiesList)
}
