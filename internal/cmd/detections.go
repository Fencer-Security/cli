package cmd

import (
	"github.com/spf13/cobra"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

var detectionCmd = &cobra.Command{
	Use:   "detection",
	Short: "Manage detections",
}

var detectionListCmd = &cobra.Command{
	Use:         "list",
	Short:       "List detections",
	Annotations: map[string]string{operationAnnotation: operations.DetectionsList.Name},
	RunE:        runDetectionList,
}

var detectionGetCmd = &cobra.Command{
	Use:         "get <slug>",
	Short:       "Get a detection by slug",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.DetectionsGet.Name},
	RunE:        runDetectionGet,
}

var (
	detectionSeverity    []string
	detectionStatus      string
	detectionAsset       []string
	detectionAssignee    []string
	detectionHasAssignee optionalBool
	detectionQuery       string
	detectionDetectedAt  string
	detectionOrderBy     string
)

func init() {
	rootCmd.AddCommand(detectionCmd)
	detectionCmd.AddCommand(detectionListCmd)
	detectionCmd.AddCommand(detectionGetCmd)

	addPaginationFlags(detectionListCmd)
	f := detectionListCmd.Flags()
	f.StringSliceVar(&detectionSeverity, "severity", nil, "Filter by severity (repeatable): critical|high|medium|low|info")
	f.StringVar(&detectionStatus, "status", "", "Filter by status")
	f.StringSliceVar(&detectionAsset, "asset", nil, "Filter by asset slug (repeatable): e.g. ARES-AJ3")
	f.StringSliceVar(&detectionAssignee, "assignee", nil, "Filter by assignee (repeatable): email or \"me\"")
	addOptionalBool(detectionListCmd, &detectionHasAssignee, "has-assignee", "Filter for assigned detections (use --has-assignee=false for unassigned)")
	f.StringVar(&detectionQuery, "q", "", "Text search across slug, title, description, asset name")
	f.StringVar(&detectionDetectedAt, "detected-at", "", "Relative time window: 24h|7d|30d|90d|365d")
	f.StringVar(&detectionOrderBy, "order-by", "", "Sort order. One of: "+operations.DetectionOrderByHelp+". Prefix with '-' for descending.")
}

func runDetectionList(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	page, err := operations.DetectionsList.Execute(cmd.Context(), client, operations.DetectionsListInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		PageInput:         operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
		Asset:             detectionAsset,
		Status:            detectionStatus,
		Severity:          detectionSeverity,
		Assignee:          detectionAssignee,
		HasAssignee:       detectionHasAssignee.Ptr(),
		Query:             detectionQuery,
		DetectedAt:        detectionDetectedAt,
		OrderBy:           operations.DetectionOrderBy(detectionOrderBy),
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, d := range page.Results {
		rows[i] = []string{d.Slug, d.Title, api.SeverityName(d.Severity), d.Status, formatAssignee(d.AssigneeEmail)}
	}
	printTable([]string{"SLUG", "TITLE", "SEVERITY", "STATUS", "ASSIGNEE"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}

func runDetectionGet(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	detection, err := operations.DetectionsGet.Execute(cmd.Context(), client, operations.DetectionsGetInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              args[0],
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(detection)
	}

	printTable([]string{"FIELD", "VALUE"}, [][]string{
		{"SLUG", detection.Slug},
		{"Title", detection.Title},
		{"Severity", api.SeverityName(detection.Severity)},
		{"Status", detection.Status},
		{"Assignee", formatAssignee(detection.AssigneeEmail)},
	})
	return nil
}
