package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/internal/auth"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke the stored OAuth token and log out",
	RunE:  runLogout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

func runLogout(cmd *cobra.Command, args []string) error {
	tokens, err := auth.LoadTokens()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	if err := auth.Revoke(tokens.BaseURL, tokens.ClientID, tokens.AccessToken); err != nil {
		fmt.Printf("Warning: failed to revoke token remotely: %v\n", err)
	}

	if err := auth.DeleteTokens(); err != nil {
		return fmt.Errorf("failed to delete local tokens: %w", err)
	}

	fmt.Println("Logged out successfully.")
	return nil
}
