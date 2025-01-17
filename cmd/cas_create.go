package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/meetwithabhishek/peeki/database"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "create CA",
	RunE: func(cmd *cobra.Command, args []string) error {
		setup, err := NewCASetup()
		if err != nil {
			return err
		}

		ca, err := database.NewCA(database.CA{Cert: setup.CACert, Key: setup.CAKey, Name: caName})
		if err != nil {
			return err
		}

		return out(ca)
	},
}

func out(i interface{}) error {
	indent, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(indent))
	return nil
}

var caName string

func init() {
	casCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	createCmd.Flags().StringVarP(&caName, "name", "n", "", "CA Name")
}
