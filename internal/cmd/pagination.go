package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"fencer/cli/internal/operations"
)

const defaultPageSize = operations.DefaultPageSize

var (
	pageFlag     int
	pageSizeFlag int
)

// addPaginationFlags attaches --page and --page-size to a list command.
// Each command declares its own flag set, so we register against the given cmd.
func addPaginationFlags(cmd *cobra.Command) {
	cmd.Flags().IntVar(&pageFlag, "page", 1, "Page number (1-indexed)")
	cmd.Flags().IntVar(&pageSizeFlag, "page-size", defaultPageSize, fmt.Sprintf("Results per page (max %d)", operations.MaxPageSize))
}

func printOperationPaginationFooter(p operations.Pagination) {
	if p.Count == 0 {
		return
	}
	fmt.Printf("\nPage %d of %d (%d total).", p.Page, p.TotalPages, p.Count)
	if p.NextPage != nil {
		fmt.Printf(" Next: --page %d.", *p.NextPage)
	}
	fmt.Println()
}
