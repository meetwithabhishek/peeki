package cmd

import (
	"fmt"
	"github.com/meetwithabhishek/peeki/database"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "peeki",
	Short: "PKI management tool",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := database.Initialize()
	if err != nil {
		fmt.Println(err)
		fmt.Println("There was an error initializing the database")
		os.Exit(1)
	}

	err = rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}
