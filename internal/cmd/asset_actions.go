package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/internal/operations"
)

var assetCriticalityScore int

var assetCriticalityCmd = &cobra.Command{
	Use:         "criticality <slug>",
	Short:       "Set the criticality score of an asset (0-100)",
	Long:        "Set the criticality score of an asset, identified by its slug (paste from `fencer asset list`).",
	Args:        cobra.ExactArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.AssetsSetCriticality.Name},
	RunE:        runAssetCriticality,
}

func init() {
	assetCmd.AddCommand(assetCriticalityCmd)

	cf := assetCriticalityCmd.Flags()
	cf.IntVar(&assetCriticalityScore, "score", 0, "Criticality score from 0 (least critical) to 100 (most critical)")
	if err := assetCriticalityCmd.MarkFlagRequired("score"); err != nil {
		panic(err)
	}
}

func runAssetCriticality(cmd *cobra.Command, args []string) error {
	if err := operations.ValidateCriticalityScore(assetCriticalityScore); err != nil {
		return fmt.Errorf("--score must be between 0 and 100")
	}

	assetSlug := args[0]

	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	if err := promptConfirm(fmt.Sprintf("Set criticality on asset %s to %d?", assetSlug, assetCriticalityScore)); err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	asset, err := operations.AssetsSetCriticality.Execute(cmd.Context(), client, operations.AssetsSetCriticalityInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Slug:              assetSlug,
		Score:             assetCriticalityScore,
	})
	if err != nil {
		return err
	}
	return assetActionOutput(asset, fmt.Sprintf("Set criticality on asset %s to %d", assetSlug, assetCriticalityScore))
}

func assetActionOutput(asset any, tableMsg string) error {
	if outputFormat == "json" {
		return outputJSON(asset)
	}
	fmt.Println(tableMsg)
	return nil
}
