package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"fencer/cli/api"
	"fencer/cli/internal/auth"
	"fencer/cli/internal/config"
	"fencer/cli/internal/version"
)

var (
	outputFormat string
	orgSlug      string
	baseURLFlag  string
	yesFlag      bool
)

var rootCmd = &cobra.Command{
	Use:          "fencer",
	Short:        "Fencer CLI — interact with the Fencer security platform",
	SilenceUsage: true,
	Version:      version.Version,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	rootCmd.PersistentFlags().StringVar(&orgSlug, "org", "", "Organization slug (or set FENCER_ORG env var)")
	rootCmd.PersistentFlags().StringVar(&baseURLFlag, "base-url", "", "Override API base URL")
	rootCmd.PersistentFlags().BoolVarP(&yesFlag, "yes", "y", false, "Skip confirmation prompts")

	if err := viper.BindEnv("org", "FENCER_ORG"); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("org", rootCmd.PersistentFlags().Lookup("org")); err != nil {
		panic(err)
	}
}

// resolveOrgSlug returns the org slug from flag, env var, or stored config.
func resolveOrgSlug() (string, error) {
	slug := viper.GetString("org")
	if slug != "" {
		return slug, nil
	}
	return "", fmt.Errorf("organization slug is required — use --org <slug> or set FENCER_ORG")
}

// resolveBaseURL returns the canonical API origin from flag or token store.
func resolveBaseURL() (string, error) {
	raw := baseURLFlag
	if raw == "" {
		tokens, err := auth.LoadTokens()
		if err == nil && tokens.BaseURL != "" {
			raw = tokens.BaseURL
		} else {
			raw = config.DefaultBaseURL
		}
	}

	normalized, err := auth.NormalizeBaseURL(raw)
	if err != nil {
		return "", err
	}

	if baseURLFlag != "" {
		tokens, err := auth.LoadTokens()
		if err == nil && tokens.BaseURL != "" {
			stored, storeErr := auth.NormalizeBaseURL(tokens.BaseURL)
			if storeErr != nil {
				return "", fmt.Errorf("stored credentials have an invalid API origin — run 'fencer login': %w", storeErr)
			}
			if !auth.SameOrigin(stored, normalized) {
				return "", auth.OriginMismatchError(stored, normalized)
			}
		}
	}
	return normalized, nil
}

// newHTTPClient is the factory used by newAPIClient. Tests may replace it with a plain client.
var newHTTPClient = func(baseURL string) *http.Client { return auth.NewAuthenticatedClient(baseURL) }

// newAPIClient creates an authenticated API client.
func newAPIClient() (*api.Client, error) {
	baseURL, err := resolveBaseURL()
	if err != nil {
		return nil, err
	}
	return api.New(baseURL, newHTTPClient(baseURL)), nil
}

// formatAsset renders an asset as "type (name)", falling back to whichever part is present.
func formatAsset(assetType, name string) string {
	switch {
	case assetType != "" && name != "":
		return fmt.Sprintf("%s (%s)", assetType, name)
	case assetType != "":
		return assetType
	default:
		return name
	}
}

// formatAssignee renders the assignee email or "—" when unassigned.
func formatAssignee(email string) string {
	if email == "" {
		return "—"
	}
	return email
}

// outputJSON writes v as indented JSON to stdout.
func outputJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeJSONOrText emits JSON when --output json is set, otherwise a table-mode message.
func writeJSONOrText(v interface{}, text string) error {
	if outputFormat == "json" {
		return outputJSON(v)
	}
	fmt.Println(text)
	return nil
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	cellStyle   = lipgloss.NewStyle().PaddingRight(2)
)

func terminalWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		return 120
	}
	return w
}

func truncateCell(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}

// printTable prints a slice of string rows with a header row, fitting the terminal width.
func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("No results.")
		return
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Shrink the widest column until the table fits the terminal.
	termW := terminalWidth()
	total := func() int {
		n := 0
		for _, w := range widths {
			n += w + 2
		}
		return n
	}
	for total() > termW {
		maxIdx := 0
		for i := 1; i < len(widths); i++ {
			if widths[i] > widths[maxIdx] {
				maxIdx = i
			}
		}
		min := len(headers[maxIdx])
		if widths[maxIdx] <= min {
			break
		}
		widths[maxIdx]--
	}

	sep := strings.Repeat("─", total())
	header := ""
	for i, h := range headers {
		header += headerStyle.Width(widths[i] + 2).Render(h)
	}
	fmt.Println(header)
	fmt.Println(sep)

	for _, row := range rows {
		line := ""
		for i, cell := range row {
			if i < len(widths) {
				line += cellStyle.Width(widths[i] + 2).Render(truncateCell(cell, widths[i]))
			}
		}
		fmt.Println(line)
	}
}
