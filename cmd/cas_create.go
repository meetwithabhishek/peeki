package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/brianvoe/gofakeit/v7"
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
	createCmd.Flags().StringVarP(&caName, "ca-name", "n", gofakeit.Noun(), "CA Name")
}
