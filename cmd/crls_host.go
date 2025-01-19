package cmd

import (
	"github.com/meetwithabhishek/peeki/internal"
	"github.com/spf13/cobra"
	"log"
	"net/http"
)

// hostCmd represents the host CRL command
var hostCmd = &cobra.Command{
	Use:   "host",
	Short: "host all crls",
	RunE: func(cmd *cobra.Command, args []string) error {
		// todo: make it more secure.
		// right now it allows access to entire play path, but we only need to host the crls inside the play path.
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
	hostCmd.Flags().StringVarP(&port, "port", "p", "3000", "port to listen on")
}
