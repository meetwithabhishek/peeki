package cmd

import (
	"github.com/spf13/cobra"
)

// issueCertCmd represents the issue command
var csrsCmd = &cobra.Command{
	Use:   "csrs",
	Short: "certificate signing request",
}

func init() {
	rootCmd.AddCommand(csrsCmd)
}
