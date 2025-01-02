/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/meetwithabhishek/peeki/internal"
	"github.com/spf13/cobra"
	"log"
	"net/http"
)

// issueCertCmd represents the issue command
var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fs := http.FileServer(http.Dir(internal.GetPlayPath()))
		http.Handle("/", fs)

		log.Print("Listening on :3000...")
		err := http.ListenAndServe(":3000", nil)
		if err != nil {
			log.Fatal(err)
		}
		return nil
	},
}

func init() {
	crlCmd.AddCommand(hostCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// issueCertCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
}
