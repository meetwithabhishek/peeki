package cmd

import (
	"github.com/spf13/cobra"
)

// crlCmd represents the crl command
var crlCmd = &cobra.Command{
	Use:   "crls",
	Short: "manage certificate revocation lists",
}

func init() {
	rootCmd.AddCommand(crlCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// crlCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
}
