/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/meetwithabhishek/peeki/internal"
	"os"

	"github.com/spf13/cobra"
)

// certsCmd represents the certs command
var certsCmd = &cobra.Command{
	Use:   "certs",
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

func init() {
	rootCmd.AddCommand(certsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// certsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// certsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
