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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
