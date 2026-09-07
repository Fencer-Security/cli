package cmd

import (
	"github.com/spf13/cobra"

	"fencer/cli/internal/operations"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage identities",
}

var identityListCmd = &cobra.Command{
	Use:         "list",
	Short:       "List identities",
	Annotations: map[string]string{operationAnnotation: operations.IdentitiesList.Name},
	RunE:        runIdentityList,
}

var (
	identityType         string
	identityStatus       string
	identityRelationship string
	identityNeedsReview  optionalBool
	identityHasOwner     optionalBool
	identityQuery        string
	identityOrderBy      string
)

func init() {
	rootCmd.AddCommand(identityCmd)
	identityCmd.AddCommand(identityListCmd)

	addPaginationFlags(identityListCmd)
	f := identityListCmd.Flags()
	f.StringVar(&identityType, "type", "", "Filter by identity_type")
	f.StringVar(&identityStatus, "status", "", "Filter by identity_status")
	f.StringVar(&identityRelationship, "relationship", "", "Filter by identity_relationship")
	addOptionalBool(identityListCmd, &identityNeedsReview, "needs-review", "Filter for identities needing review (use --needs-review=false to invert)")
	addOptionalBool(identityListCmd, &identityHasOwner, "has-owner", "Filter for identities with an owner (use --has-owner=false for orphaned)")
	f.StringVar(&identityQuery, "q", "", "Text search across display name, email, vendor username")
	f.StringVar(&identityOrderBy, "order-by", "", "Sort order. One of: "+operations.IdentityOrderByHelp+". Prefix with '-' for descending.")
}

func runIdentityList(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	page, err := operations.IdentitiesList.Execute(cmd.Context(), client, operations.IdentitiesListInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		PageInput:         operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
		Type:              identityType,
		Status:            identityStatus,
		Relationship:      identityRelationship,
		NeedsReview:       identityNeedsReview.Ptr(),
		HasOwner:          identityHasOwner.Ptr(),
		Query:             identityQuery,
		OrderBy:           operations.IdentityOrderBy(identityOrderBy),
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, id := range page.Results {
		rows[i] = []string{id.Slug, id.Name, id.Email, id.IdentityType}
	}
	printTable([]string{"SLUG", "NAME", "EMAIL", "TYPE"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}
