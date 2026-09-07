package cmd

import (
	"strconv"

	"github.com/spf13/cobra"
)

// optionalBool is a tri-valued flag (unset / true / false) implementing pflag.Value.
// Combined with NoOptDefVal="true" it lets `--flag` mean true, `--flag=false` mean
// false, and absence mean "no filter".
type optionalBool struct {
	value *bool
}

func (b *optionalBool) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	b.value = &v
	return nil
}

func (b *optionalBool) String() string {
	if b.value == nil {
		return ""
	}
	return strconv.FormatBool(*b.value)
}

func (b *optionalBool) Type() string { return "bool" }

func (b *optionalBool) reset() { b.value = nil }

func (b optionalBool) Ptr() *bool { return b.value }

// addOptionalBool registers an optionalBool flag that accepts `--flag` (true) or
// `--flag=false` (false), and stays unset when the caller omits it.
func addOptionalBool(cmd *cobra.Command, target *optionalBool, name, usage string) {
	cmd.Flags().Var(target, name, usage)
	cmd.Flags().Lookup(name).NoOptDefVal = "true"
}
