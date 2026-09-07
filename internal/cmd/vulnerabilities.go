package cmd

import (
	"github.com/spf13/cobra"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Manage vulnerabilities",
}

var vulnListCmd = &cobra.Command{
	Use:         "list",
	Short:       "List vulnerabilities",
	Annotations: map[string]string{operationAnnotation: operations.VulnerabilitiesList.Name},
	Long: `List vulnerabilities in the current organization.

Only open findings are listed by default — resolved history is usually far
larger and rarely what you want. Pass --status all for every status, or
--status resolved|ready_for_verification to select one.

Use --query/-q for free-text search by package or technology name. The query
matches title, description, and slug — dependency findings are titled
"Vulnerable package: <name>@<version>", so --query celery finds every
celery-related finding. Combine filters to narrow the result set.`,
	Example: `  # Find vulnerabilities mentioning a package or technology
  fencer vuln list --query celery
  fencer vuln list -q rabbitmq --status open

  # Open critical/high findings that are live in production
  fencer vuln list --severity critical --severity high --status open --live

  # Findings on a specific asset, sorted newest first
  fencer vuln list --asset ARES-AJ3 --order-by -first_seen`,
	RunE: runVulnList,
}

var vulnGetCmd = &cobra.Command{
	Use:         "get <slug>",
	Short:       "Get a vulnerability by slug",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.VulnerabilitiesGet.Name},
	RunE:        runVulnGet,
}

var (
	vulnSeverity    []string
	vulnStatus      string
	vulnCategory    string
	vulnAsset       []string
	vulnAssignee    []string
	vulnQuery       string
	vulnLive        optionalBool
	vulnIgnored     optionalBool
	vulnDeferred    optionalBool
	vulnHasAssignee optionalBool
	vulnPriority    []string
	vulnInScope     optionalBool
	vulnOrderBy     string
)

func init() {
	rootCmd.AddCommand(vulnCmd)
	vulnCmd.AddCommand(vulnListCmd)
	vulnCmd.AddCommand(vulnGetCmd)

	addPaginationFlags(vulnListCmd)
	f := vulnListCmd.Flags()
	f.StringSliceVar(&vulnSeverity, "severity", nil, "Filter by severity (repeatable): critical|high|medium|low|info")
	f.StringVar(&vulnStatus, "status", "", "Filter by status: open|ready_for_verification|resolved|all (default: open)")
	f.StringVar(&vulnCategory, "category", "", "Filter by category: "+operations.VulnerabilityCategoryHelp)
	f.StringSliceVar(&vulnAsset, "asset", nil, "Filter by asset slug from the ASSET column (repeatable): e.g. ARES-AJ3")
	f.StringSliceVar(&vulnAssignee, "assignee", nil, "Filter by assignee (repeatable): email or \"me\"")
	f.StringVarP(&vulnQuery, "query", "q", "", "Text search across title, description, and slug. Use this for package or technology names — e.g. --query celery matches dependency findings titled \"Vulnerable package: celery@…\".")
	addOptionalBool(vulnListCmd, &vulnLive, "live", "Filter for live vulnerabilities (use --live=false to invert)")
	addOptionalBool(vulnListCmd, &vulnIgnored, "ignored", "Filter for ignored vulnerabilities (use --ignored=false to invert)")
	addOptionalBool(vulnListCmd, &vulnDeferred, "deferred", "Filter for deferred vulnerabilities (use --deferred=false to invert)")
	addOptionalBool(vulnListCmd, &vulnHasAssignee, "has-assignee", "Filter for assigned vulnerabilities (use --has-assignee=false for unassigned)")
	f.StringSliceVar(&vulnPriority, "priority", nil, "Filter by priority (repeatable): "+operations.PriorityLevelHelp())
	addOptionalBool(vulnListCmd, &vulnInScope, "in-scope", "Filter for in-scope vulnerabilities (use --in-scope=false to invert)")
	f.StringVar(&vulnOrderBy, "order-by", "", "Sort order. One of: "+operations.VulnerabilityOrderByHelp+". Prefix with '-' for descending (e.g. -first_seen).")
}

func runVulnList(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	page, err := operations.VulnerabilitiesList.Execute(cmd.Context(), client, operations.VulnerabilitiesListInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		PageInput:         operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
		Asset:             vulnAsset,
		Status:            vulnStatus,
		Category:          operations.VulnerabilityCategory(vulnCategory),
		Severity:          vulnSeverity,
		PriorityLevel:     operations.MapStrings[operations.PriorityLevel](vulnPriority),
		Query:             vulnQuery,
		Assignee:          vulnAssignee,
		HasAssignee:       vulnHasAssignee.Ptr(),
		Live:              vulnLive.Ptr(),
		Ignored:           vulnIgnored.Ptr(),
		Deferred:          vulnDeferred.Ptr(),
		InScope:           vulnInScope.Ptr(),
		OrderBy:           operations.VulnerabilityOrderBy(vulnOrderBy),
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, v := range page.Results {
		rows[i] = []string{v.Slug, v.Title, api.SeverityName(v.Severity), v.Status, v.AssetResourceSlug, v.AssetResourceKind, v.AssetName, formatAssignee(v.AssigneeEmail), v.WebURL}
	}
	printTable([]string{"SLUG", "TITLE", "SEVERITY", "STATUS", "ASSET", "KIND", "NAME", "ASSIGNEE", "URL"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}

func runVulnGet(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	vuln, err := operations.VulnerabilitiesGet.Execute(cmd.Context(), client, operations.VulnerabilitiesGetInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              args[0],
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(vuln)
	}

	printTable([]string{"FIELD", "VALUE"}, [][]string{
		{"Slug", vuln.Slug},
		{"Title", vuln.Title},
		{"Severity", api.SeverityName(vuln.Severity)},
		{"Status", vuln.Status},
		{"Asset", vuln.AssetResourceSlug},
		{"Kind", vuln.AssetResourceKind},
		{"Name", vuln.AssetName},
		{"Assignee", formatAssignee(vuln.AssigneeEmail)},
		{"URL", vuln.WebURL},
	})
	return nil
}
