package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/x/term"
)

// confirmReader is the stdin reader used by promptConfirm. Tests can replace it.
var confirmReader io.Reader = os.Stdin

// isStdinTTY reports whether stdin is a terminal. Overridable in tests.
var isStdinTTY = func() bool { return term.IsTerminal(os.Stdin.Fd()) }

// promptConfirm returns nil if --yes is set, or if the user answers y/Y/yes to the prompt.
// Returns an error in non-TTY mode unless --yes is set.
func promptConfirm(msg string) error {
	if yesFlag {
		return nil
	}
	if !isStdinTTY() {
		return fmt.Errorf("%s — pass --yes (-y) to confirm in non-interactive mode", msg)
	}
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", msg)
	reader := bufio.NewReader(confirmReader)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "y" || answer == "yes" {
		return nil
	}
	return fmt.Errorf("cancelled")
}
