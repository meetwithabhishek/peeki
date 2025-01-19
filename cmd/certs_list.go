package cmd

import (
	"github.com/meetwithabhishek/peeki/database"
	"github.com/spf13/cobra"
)

// listCertsCmd represents the list certificates command
var listCertsCmd = &cobra.Command{
	Use:   "list",
	Short: "list certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		certs, err := database.ListCerts()
		if err != nil {
			return err
		}
		return out(certs)
	},
}

func init() {
	certsCmd.AddCommand(listCertsCmd)
}
