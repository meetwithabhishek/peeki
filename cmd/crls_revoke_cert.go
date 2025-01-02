/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/x509"
	"fmt"
	"github.com/ansel1/merry/v2"
	"github.com/spf13/cobra"
	"math/big"
	"time"
)

// issueCertCmd represents the issue command
var revokeCertCmd = &cobra.Command{
	Use:   "revoke-cert",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {

		/*		cert, err := MustParseCertificateString(`-----BEGIN CERTIFICATE-----
				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
				N7TjoN9NGCrqxcagujLvTWs=
				-----END CERTIFICATE-----`)
						if err != nil {
							return err
						}
		*/
		// Create a new big.Int
		bigInt := new(big.Int)

		// Parse the string into the big.Int, using base 10
		_, ok := bigInt.SetString(serialNumber, 10)
		if !ok {
			return merry.New("Failed to set serial number")
		}

		fmt.Println(bigInt.String())
		list := []x509.RevocationListEntry{{
			SerialNumber:   bigInt,
			RevocationTime: time.Now(),
		}}

		err := issueCRL(caName, list)
		if err != nil {
			return err
		}
		return nil
	},
}

var serialNumber string

func init() {
	crlCmd.AddCommand(revokeCertCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// issueCertCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	revokeCertCmd.Flags().StringVarP(&caName, "ca-name", "", "", "CA Name")
	revokeCertCmd.Flags().StringVarP(&serialNumber, "serial-number", "", "", "Serial Number of Certificate")
}
