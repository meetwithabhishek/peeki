package cmd

import (
	"github.com/spf13/cobra"
)

// crlCmd represents the crls command
var crlCmd = &cobra.Command{
	Use:   "crls",
	Short: "manage certificate revocation lists",
}

func init() {
	rootCmd.AddCommand(crlCmd)
}
