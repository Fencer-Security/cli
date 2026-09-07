package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/internal/operations"
)

var assetCmd = &cobra.Command{
	Use:   "asset",
	Short: "Manage assets",
}

var assetListCmd = &cobra.Command{
	Use:         "list",
	Short:       "List assets",
	Annotations: map[string]string{operationAnnotation: operations.AssetsList.Name},
	RunE:        runAssetList,
}

var assetGetCmd = &cobra.Command{
	Use:         "get <slug>",
	Short:       "Get an asset by slug",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.AssetsGet.Name},
	RunE:        runAssetGet,
}

var (
	assetKind     string
	assetOrderBy  string
	assetTopLevel bool
)

func init() {
	rootCmd.AddCommand(assetCmd)
	assetCmd.AddCommand(assetListCmd)
	assetCmd.AddCommand(assetGetCmd)
	assetCmd.AddCommand(assetFiltersCmd)

	addPaginationFlags(assetListCmd)
	f := assetListCmd.Flags()
	f.StringVar(&assetKind, "kind", "", "Filter by asset kind (run 'fencer asset filters kind' for valid values)")
	f.StringVar(&assetOrderBy, "order-by", "", "Sort order: "+operations.AssetOrderByHelp+". Prefix with '-' for descending.")
	f.BoolVar(&assetTopLevel, "top-level", false, "Only show top-level resources (no parent)")
}

func runAssetList(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	input := operations.AssetsListInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		PageInput:         operations.PageInput{Page: pageFlag, PageSize: pageSizeFlag},
		Kind:              assetKind,
		OrderBy:           operations.AssetOrderBy(assetOrderBy),
	}
	if assetTopLevel {
		topLevel := true
		input.TopLevel = &topLevel
	}

	page, err := operations.AssetsList.Execute(cmd.Context(), client, input)
	if err != nil {
		return err
	}

	if assetKind != "" && page.Pagination.Count == 0 && outputFormat != "json" {
		resolved, rerr := resolveAssetKind(client, slug, assetKind)
		if rerr != nil {
			return rerr
		}
		if resolved != assetKind {
			assetKind = resolved
			input.Kind = resolved
			page, err = operations.AssetsList.Execute(cmd.Context(), client, input)
			if err != nil {
				return err
			}
		}
	}

	if outputFormat == "json" {
		return outputJSON(page)
	}

	rows := make([][]string, len(page.Results))
	for i, a := range page.Results {
		name := a.Description
		if name == "" {
			name = a.Slug
		}
		rows[i] = []string{a.Slug, name, a.KindName, a.ProviderName, fmt.Sprintf("%d", a.Criticality), a.BelongsTo}
	}
	printTable([]string{"SLUG", "NAME", "KIND", "PROVIDER", "CRITICALITY", "BELONGS TO"}, rows)
	printOperationPaginationFooter(page.Pagination)
	return nil
}

func runAssetGet(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	asset, err := operations.AssetsGet.Execute(cmd.Context(), client, operations.AssetsGetInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              args[0],
	})
	if err != nil {
		return err
	}

	if outputFormat == "json" {
		return outputJSON(asset)
	}

	name := asset.Description
	if name == "" {
		name = asset.Slug
	}
	printTable([]string{"FIELD", "VALUE"}, [][]string{
		{"Slug", asset.Slug},
		{"Name", name},
		{"Kind", asset.KindName},
		{"Provider", asset.ProviderName},
		{"Category", asset.Category},
		{"Criticality", fmt.Sprintf("%d", asset.Criticality)},
		{"Belongs to", asset.BelongsTo},
		{"Type", asset.AssetType},
	})
	return nil
}
