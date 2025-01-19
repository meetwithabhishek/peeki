package cmd

import (
	"github.com/spf13/cobra"
)

// csrsCmd represents the CSRs command
var csrsCmd = &cobra.Command{
	Use:   "csrs",
	Short: "certificate signing request",
}

func init() {
	rootCmd.AddCommand(csrsCmd)
}
