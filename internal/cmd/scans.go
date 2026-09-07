package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Manage scans",
}

var scanListCmd = &cobra.Command{
	Use:         "list",
	Short:       "List scans for an asset",
	Annotations: map[string]string{operationAnnotation: operations.ScansList.Name},
	RunE:        runScanList,
}

var (
	scanListAsset  string
	scanListBranch string
)

var scanGetCmd = &cobra.Command{
	Use:         "get <slug>",
	Short:       "Get a scan by slug",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.ScansGet.Name},
	RunE:        runScanGet,
}

var scanVulnsCmd = &cobra.Command{
	Use:         "vulns <slug>",
	Short:       "List vulnerabilities found by a scan",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.ScansListVulnerabilities.Name},
	RunE:        runScanVulns,
}

var scanDiffCmd = &cobra.Command{
	Use:         "diff <slug>",
	Short:       "Show vulnerabilities new in and resolved by a scan",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.ScansDiff.Name},
	RunE:        runScanDiff,
}

var scanScheduleCmd = &cobra.Command{
	Use:         "schedule <asset-slug>",
	Short:       "Schedule a manual scan of an asset",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.ScansSchedule.Name},
	RunE:        runScanSchedule,
}

var scanScheduleBranch string

var (
	scanVulnsNew      optionalBool
	scanVulnsResolved optionalBool
	scanVulnsIgnored  optionalBool
	scanVulnsSeverity []string
	scanVulnsStatus   string
	scanVulnsCategory string
	scanVulnsQuery    string
	scanVulnsOrderBy  string
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanListCmd)
	scanCmd.AddCommand(scanGetCmd)
	scanCmd.AddCommand(scanVulnsCmd)
	scanCmd.AddCommand(scanDiffCmd)
	scanCmd.AddCommand(scanScheduleCmd)
	scanScheduleCmd.Flags().StringVar(&scanScheduleBranch, "branch", "", "Branch to scan (repository assets only)")

	addPaginationFlags(scanListCmd)
	scanListCmd.Flags().StringVar(&scanListAsset, "asset", "", "Asset slug (e.g. ARES-AJ3)")
	scanListCmd.Flags().StringVar(&scanListBranch, "branch", "", "Filter by branch (code-scan assets only)")
	if err := scanListCmd.MarkFlagRequired("asset"); err != nil {
		panic(err)
	}

	addPaginationFlags(scanVulnsCmd)
	f := scanVulnsCmd.Flags()
	addOptionalBool(scanVulnsCmd, &scanVulnsNew, "new", "Filter for findings new in this scan (use --new=false to invert)")
	addOptionalBool(scanVulnsCmd, &scanVulnsResolved, "resolved", "Filter for findings resolved by this scan (use --resolved=false to invert)")
	addOptionalBool(scanVulnsCmd, &scanVulnsIgnored, "ignored", "Filter for ignored findings (use --ignored=false to invert)")
	f.StringSliceVar(&scanVulnsSeverity, "severity", nil, "Filter by severity (repeatable): critical|high|medium|low|info")
	f.StringVar(&scanVulnsStatus, "status", "", "Filter by status")
	f.StringVar(&scanVulnsCategory, "category", "", "Filter by category: "+operations.ScanVulnerabilityCategoryHelp)
	f.StringVar(&scanVulnsQuery, "q", "", "Text search across description and slug")
	f.StringVar(&scanVulnsOrderBy, "order-by", "", "Sort order: "+operations.ScanVulnerabilityOrderByHelp+". Prefix with '-' for descending.")
}

func runScanVulns(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	page, err := operations.ScansListVulnerabilities.Execute(cmd.Context(), client, operations.ScansListVulnerabilitiesInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		PageInput:         operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
		Slug:              args[0],
		New:               scanVulnsNew.Ptr(),
		Resolved:          scanVulnsResolved.Ptr(),
		Ignored:           scanVulnsIgnored.Ptr(),
		Severity:          scanVulnsSeverity,
		Status:            scanVulnsStatus,
		Category:          operations.ScanVulnerabilityCategory(scanVulnsCategory),
		Query:             scanVulnsQuery,
		OrderBy:           operations.ScanVulnerabilityOrderBy(scanVulnsOrderBy),
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, v := range page.Results {
		rows[i] = []string{
			v.Slug,
			v.Title,
			api.SeverityName(v.Severity),
			v.DisplayStatus,
			v.Category,
			v.LocationTitle,
		}
	}
	printTable([]string{"SLUG", "TITLE", "SEVERITY", "STATE", "CATEGORY", "LOCATION"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}

func runScanList(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	if scanListAsset == "" {
		return fmt.Errorf("--asset is required")
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	page, err := operations.ScansList.Execute(cmd.Context(), client, operations.ScansListInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		PageInput:         operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
		Asset:             scanListAsset,
		Branch:            scanListBranch,
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, s := range page.Results {
		rows[i] = []string{
			s.Slug,
			s.Status,
			s.CreatedAt,
			scanTrigger(s),
			s.Branch,
			fmt.Sprintf("%d", s.CountVulnerabilities),
			fmt.Sprintf("%d", s.CountNew),
			fmt.Sprintf("%d", s.CountCritical),
			fmt.Sprintf("%d", s.CountHigh),
		}
	}
	printTable([]string{"SLUG", "STATUS", "CREATED", "TRIGGER", "BRANCH", "VULNS", "NEW", "CRIT", "HIGH"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}

func scanTrigger(s operations.Scan) string {
	if s.TriggerDescription != "" {
		return s.TriggerDescription
	}
	if s.TriggerByName != "" {
		return fmt.Sprintf("%s (%s)", s.TriggerType, s.TriggerByName)
	}
	return s.TriggerType
}

func runScanGet(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	scan, err := operations.ScansGet.Execute(cmd.Context(), client, operations.ScansGetInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              args[0],
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(scan)
	}

	rows := [][]string{
		{"Slug", scan.Slug},
		{"Status", scan.Status},
		{"Asset", formatAsset(scan.AssetType, scan.AssetName)},
	}
	if scan.Branch != "" {
		rows = append(rows, []string{"Branch", scan.Branch})
	}
	rows = append(rows,
		[]string{"Queued at", scan.QueuedAt},
		[]string{"Started at", scan.StartedAt},
		[]string{"Finished at", scan.FinishedAt},
		[]string{"Duration (s)", formatDuration(scan.DurationSeconds)},
		[]string{"Trigger", scanDetailTrigger(scan)},
		[]string{"New", fmt.Sprintf("%d", scan.Counts.CountNew)},
		[]string{"Open", fmt.Sprintf("%d", scan.Counts.CountOpen)},
		[]string{"Existing", fmt.Sprintf("%d", scan.Counts.CountExisting)},
		[]string{"Resolved", fmt.Sprintf("%d", scan.Counts.CountResolved)},
		[]string{"Ignored", fmt.Sprintf("%d", scan.Counts.CountIgnored)},
		[]string{"Critical+High", fmt.Sprintf("%d", scan.Counts.CountCriticalHigh)},
	)
	if scan.FailedReason != "" {
		rows = append(rows, []string{"Failed reason", scan.FailedReason})
	}
	if scan.ErrorSuggestion != "" {
		rows = append(rows, []string{"Error suggestion", scan.ErrorSuggestion})
	}
	printTable([]string{"FIELD", "VALUE"}, rows)
	return nil
}

func runScanDiff(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	diff, err := operations.ScansDiff.Execute(cmd.Context(), client, operations.ScansDiffInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              args[0],
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(diff)
	}

	printScanDiffSection("New", diff.New)
	fmt.Println()
	printScanDiffSection("Resolved", diff.Resolved)
	return nil
}

func printScanDiffSection(label string, results []operations.VulnerabilitySnapshot) {
	fmt.Printf("=== %s (%d) ===\n", label, len(results))
	if len(results) == 0 {
		return
	}
	rows := make([][]string, len(results))
	for i, v := range results {
		rows[i] = []string{v.Slug, v.Title, api.SeverityName(v.Severity), v.Category, v.LocationTitle}
	}
	printTable([]string{"SLUG", "TITLE", "SEVERITY", "CATEGORY", "LOCATION"}, rows)
}

func scanDetailTrigger(s operations.ScanDetail) string {
	if s.TriggerDescription != "" {
		return s.TriggerDescription
	}
	return s.TriggerType
}

func formatDuration(d *float64) string {
	if d == nil {
		return ""
	}
	return fmt.Sprintf("%.2f", *d)
}

// scanScheduleConfirmMessage builds the y/N prompt for `scan schedule`. When the
// asset metadata can be fetched, the message names the asset type and description;
// otherwise it falls back to the slug alone. With --yes the message is never shown,
// so skip the metadata fetch entirely.
func scanScheduleConfirmMessage(client *api.Client, orgSlug, assetSlug string) string {
	if yesFlag {
		return ""
	}
	asset, err := client.GetAssetResource(orgSlug, assetSlug)
	if err != nil || asset == nil {
		return fmt.Sprintf("Schedule a scan of asset %s?", assetSlug)
	}
	assetType := asset.AssetType
	if assetType == "" {
		assetType = "asset"
	}
	if asset.Description == "" {
		return fmt.Sprintf("Schedule a scan of %s %s?", assetType, assetSlug)
	}
	return fmt.Sprintf("Schedule a scan of %s %s (%s)?", assetType, asset.Description, assetSlug)
}

func runScanSchedule(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}
	assetSlug := args[0]

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	if err := promptConfirm(scanScheduleConfirmMessage(client, slug, assetSlug)); err != nil {
		return err
	}

	resp, err := operations.ScansSchedule.Execute(cmd.Context(), client, operations.ScansScheduleInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              assetSlug,
		Branch:            scanScheduleBranch,
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(resp)
	}

	if resp.Slug != nil && *resp.Slug != "" {
		fmt.Printf("Scheduled scan %s for asset %s\n", *resp.Slug, assetSlug)
	} else {
		fmt.Println(resp.Message)
	}
	return nil
}
