package cmd

import (
	"github.com/meetwithabhishek/peeki/database"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var listCAsCmd = &cobra.Command{
	Use:   "list",
	Short: "list cas",
	RunE: func(cmd *cobra.Command, args []string) error {
		as, err := database.ListCAs()
		if err != nil {
			return err
		}
		return out(as)
	},
}

func init() {
	casCmd.AddCommand(listCAsCmd)
}
