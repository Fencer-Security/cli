package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"fencer/cli/api"
	"fencer/cli/internal/operations"
)

// kindFilterField is the asset inventory config key that the `--kind` flag filters on.
const kindFilterField = "kind"

var assetFiltersCmd = &cobra.Command{
	Use:   "filters [field]",
	Short: "List valid asset filter fields and their values",
	Long: "List the asset inventory filter fields and the valid values for each.\n\n" +
		"Run without arguments to see the available fields, or pass a field name\n" +
		"(e.g. \"kind\") to list its valid values. The \"kind\" values are what the\n" +
		"`asset list --kind` flag accepts.",
	Args:        cobra.MaximumNArgs(1),
	Annotations: map[string]string{operationAnnotation: operations.AssetsFilters.Name},
	RunE:        runAssetFilters,
}

func runAssetFilters(cmd *cobra.Command, args []string) error {
	slug, err := resolveOrgSlug()
	if err != nil {
		return err
	}

	client, err := newAPIClient()
	if err != nil {
		return err
	}

	field := ""
	if len(args) == 1 {
		field = args[0]
	}
	out, err := operations.AssetsFilters.Execute(cmd.Context(), client, operations.AssetsFiltersInput{
		OrganizationInput: operations.OrganizationInput{OrganizationSlug: slug},
		Field:             field,
	})
	if err != nil {
		return err
	}

	if field != "" {
		return outputFilterValues(*out.Values)
	}
	return outputFilterFields(out.Filters)
}

func outputFilterFields(filters map[string]operations.FilterConfig) error {
	if outputFormat == "json" {
		return outputJSON(filters)
	}

	fields := sortedFilterFieldNames(filters)
	rows := make([][]string, len(fields))
	for i, field := range fields {
		fc := filters[field]
		rows[i] = []string{field, fc.Label, fmt.Sprintf("%d", len(fc.Options))}
	}
	printTable([]string{"FIELD", "LABEL", "VALUES"}, rows)
	if len(rows) > 0 {
		fmt.Println("\nRun 'fencer asset filters <field>' to list valid values.")
	}
	return nil
}

func outputFilterValues(fc operations.FilterConfig) error {
	if outputFormat == "json" {
		return outputJSON(fc)
	}

	rows := make([][]string, len(fc.Options))
	for i, opt := range fc.Options {
		rows[i] = []string{opt.Value, opt.Label}
	}
	printTable([]string{"VALUE", "LABEL"}, rows)
	return nil
}

func sortedFilterFieldNames(filters map[string]operations.FilterConfig) []string {
	fields := make([]string, 0, len(filters))
	for field := range filters {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

// resolveAssetKind validates the user-supplied --kind value against the kinds that
// actually exist in the org's asset inventory. It returns the canonical kind value
// to send to the API, or an error with a "did you mean" suggestion when the input
// does not match a known kind. Validation is best-effort: if the config cannot be
// fetched, or no kinds are available, the input is passed through unchanged.
func resolveAssetKind(client *api.Client, orgSlug, input string) (string, error) {
	cfg, err := client.GetAssetInventoryConfig(orgSlug)
	if err != nil {
		return input, nil
	}
	options := cfg.Filters[kindFilterField].Options
	if len(options) == 0 {
		return input, nil
	}

	for _, opt := range options {
		if strings.EqualFold(opt.Value, input) {
			return opt.Value, nil
		}
	}

	if suggestion, ok := suggestFilterValue(input, options); ok {
		return "", fmt.Errorf("%q is not a valid asset type. Did you mean %q?\nRun 'fencer asset filters kind' to list valid asset types", input, suggestion)
	}
	return "", fmt.Errorf("%q is not a valid asset type.\nRun 'fencer asset filters kind' to list valid asset types", input)
}

// suggestFilterValue finds the option whose value or label most closely matches the
// input and returns its canonical value. It favours prefix and substring matches
// over edit distance, and returns ok=false when nothing is close enough to suggest.
func suggestFilterValue(input string, options []api.FilterOption) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(input))
	normU := strings.ReplaceAll(norm, " ", "_")

	bestValue := ""
	bestScore := -1
	for _, opt := range options {
		candidates := []string{strings.ToLower(opt.Value), strings.ToLower(opt.Label)}
		score := matchScore([]string{norm, normU}, candidates)
		if bestScore == -1 || score < bestScore {
			bestScore = score
			bestValue = opt.Value
		}
	}

	if bestScore < 0 || bestScore > maxSuggestionDistance {
		return "", false
	}
	return bestValue, true
}

// maxSuggestionDistance is the largest match score for which a "did you mean"
// suggestion is offered. Prefix matches score 1 and substring matches score 2, so
// this also tolerates small typos (edit distance up to 3).
const maxSuggestionDistance = 3

// matchScore returns the best (lowest) score between any input variant and any
// candidate string: 0 for an exact match, 1 for a shared prefix, 2 for a substring
// containment, otherwise the Levenshtein edit distance.
func matchScore(inputs, candidates []string) int {
	best := -1
	for _, in := range inputs {
		for _, cand := range candidates {
			score := pairScore(in, cand)
			if best == -1 || score < best {
				best = score
			}
		}
	}
	return best
}

func pairScore(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "" || b == "":
		return levenshtein(a, b)
	case strings.HasPrefix(a, b) || strings.HasPrefix(b, a):
		return 1
	case strings.Contains(a, b) || strings.Contains(b, a):
		return 2
	default:
		return levenshtein(a, b)
	}
}

// levenshtein returns the edit distance between two strings.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = minInt(minInt(prev[j]+1, curr[j-1]+1), prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
