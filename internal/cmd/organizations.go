package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"fencer/cli/internal/operations"
)

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Manage organizations",
}

var orgListCmd = &cobra.Command{
	Use:         "list",
	Short:       "List organizations",
	Annotations: map[string]string{operationAnnotation: operations.OrganizationsList.Name},
	RunE:        runOrgList,
}

var orgUseCmd = &cobra.Command{
	Use:   "use <slug>",
	Short: "Set the default organization",
	Args:  cobra.ExactArgs(1),
	RunE:  runOrgUse,
}

func init() {
	rootCmd.AddCommand(orgCmd)
	orgCmd.AddCommand(orgListCmd)
	orgCmd.AddCommand(orgUseCmd)

	addPaginationFlags(orgListCmd)
}

func runOrgList(cmd *cobra.Command, args []string) error {
	client, err := newAPIClient()
	if err != nil {
		return err
	}

	page, err := operations.OrganizationsList.Execute(cmd.Context(), client, operations.OrganizationsListInput{
		PageInput: operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, o := range page.Results {
		rows[i] = []string{o.Name, o.Slug}
	}
	printTable([]string{"NAME", "SLUG"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}

func runOrgUse(cmd *cobra.Command, args []string) error {
	slug := args[0]
	viper.Set("org", slug)
	if outputFormat == "json" {
		return outputJSON(map[string]string{"organization_slug": slug})
	}
	fmt.Printf("Default organization set to: %s\n", slug)
	fmt.Println("Note: this is session-scoped. Use FENCER_ORG env var for persistence.")
	return nil
}
