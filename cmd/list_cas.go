/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

// listCasCmd represents the list command
var listCasCmd = &cobra.Command{
	Use:   "list",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		as, err := listCAs()
		if err != nil {
			return err
		}
		fmt.Println(as)
		return nil
	},
}

func listCAs() ([]string, error) {
	files, err := os.ReadDir(getCAsPath())
	if err != nil {
		return nil, err
	}

	dirs := []string{}

	for _, file := range files {
		if file.IsDir() {
			dirs = append(dirs, file.Name())
		}
	}

	return dirs, nil
}

func init() {
	casCmd.AddCommand(listCasCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCasCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCasCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
