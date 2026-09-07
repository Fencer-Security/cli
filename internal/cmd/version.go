package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/internal/config"
	"fencer/cli/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the Fencer CLI version and build information",
	Args:  cobra.NoArgs,
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(_ *cobra.Command, _ []string) error {
	info := version.Current(config.DefaultBaseURL)
	if outputFormat == "json" {
		return outputJSON(info)
	}
	fmt.Printf("fencer %s\n", info.Version)
	fmt.Printf("commit  %s\n", info.Commit)
	fmt.Printf("built   %s\n", info.Date)
	fmt.Printf("os/arch %s/%s\n", info.GoOS, info.GoArch)
	fmt.Printf("api     %s\n", info.DefaultBaseURL)
	return nil
}
