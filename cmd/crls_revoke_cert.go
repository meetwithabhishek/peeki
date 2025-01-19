package cmd

import (
	"crypto/x509"
	"fmt"
	"github.com/ansel1/merry/v2"
	"github.com/spf13/cobra"
	"math/big"
	"time"
)

// revokeCertCmd represents the revoke certificate command
var revokeCertCmd = &cobra.Command{
	Use:   "revoke-cert",
	Short: "revoke a certificate",
	Long:  `Add a serial number of the certificate to the CRL`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
	revokeCertCmd.Flags().StringVarP(&caName, "ca-name", "n", "", "CA Name")
	revokeCertCmd.Flags().StringVarP(&serialNumber, "serial-number", "s", "", "Serial Number of Certificate")
}
