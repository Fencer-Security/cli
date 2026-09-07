package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"fencer/cli/internal/auth"
	"fencer/cli/internal/config"
)

var tokenFlag string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the Fencer API via OAuth or a service account token",
	RunE:  runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVar(&tokenFlag, "token", "", "Service account token (or set FENCER_TOKEN)")
}

func runLogin(cmd *cobra.Command, args []string) error {
	raw := baseURLFlag
	if raw == "" {
		raw = config.DefaultBaseURL
	}
	baseURL, err := auth.NormalizeBaseURL(raw)
	if err != nil {
		return err
	}

	if token := serviceAccountToken(); token != "" {
		// Expiry is enforced by the server; the CLI stores none for service-account tokens.
		tokens := &auth.TokenData{
			BaseURL:     baseURL,
			AccessToken: token,
		}
		if err := auth.SaveTokens(tokens); err != nil {
			return fmt.Errorf("failed to save tokens: %w", err)
		}
		fmt.Println("Login successful! Service account token saved.")
		return nil
	}

	fmt.Printf("Authenticating with %s...\n", baseURL)
	clientID, tokens, err := auth.Authenticate(baseURL)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	tokens.BaseURL = baseURL
	tokens.ClientID = clientID

	if err := auth.SaveTokens(tokens); err != nil {
		return fmt.Errorf("failed to save tokens: %w", err)
	}

	fmt.Println("Login successful! Token saved.")
	return nil
}

func serviceAccountToken() string {
	if tokenFlag != "" {
		return strings.TrimSpace(tokenFlag)
	}
	return strings.TrimSpace(os.Getenv("FENCER_TOKEN"))
}
