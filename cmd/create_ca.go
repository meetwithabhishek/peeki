/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/meetwithabhishek/peeki/internal"
	"github.com/spf13/cobra"
	"os"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := os.MkdirAll(getCAsPath(caName), 0755)
		if err != nil {
			return err
		}

		setup, err := NewCASetup()
		if err != nil {
			return err
		}

		err = internal.WriteToFile(getCAsPath(caName, internal.CAKey), []byte(setup.CAKey))
		if err != nil {
			return err
		}

		err = internal.WriteToFile(getCAsPath(caName, internal.CACrt), []byte(setup.CACert))
		if err != nil {
			return err
		}

		return nil
	},
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
