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
	Short: "host all crls",
	RunE: func(cmd *cobra.Command, args []string) error {
		fs := http.FileServer(http.Dir(internal.GetPlayPath()))
		http.Handle("/", fs)

		log.Printf("Listening on :%s...", port)
		err := http.ListenAndServe(":"+port, nil)
		if err != nil {
			log.Fatal(err)
		}
		return nil
	},
}

var port string

func init() {
	crlCmd.AddCommand(hostCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// issueCertCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	hostCmd.Flags().StringVarP(&port, "port", "p", "3000", "port to listen on")
}
