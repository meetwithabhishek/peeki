package cmd

import (
	"github.com/meetwithabhishek/peeki/database"
	"github.com/spf13/cobra"
)

// issueCertCmd represents the issue command
var issueCertCmd = &cobra.Command{
	Use:   "issue",
	Short: "issue a certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		cert, err := issueCert()
		if err != nil {
			return err
		}
		return out(cert)
	},
}

func issueCert() (*database.Cert, error) {
	ca, err := database.GetCA(caName)
	if err != nil {
		return nil, err
	}

	resp, err := issueCertStandalone(IssueCertReq{
		caName:     caName,
		caCert:     ca.Cert,
		caKey:      ca.Key,
		commonName: commonName,
	})
	if err != nil {
		return nil, err
	}

	cert, err := database.NewCert(database.Cert{
		CAID:         ca.ID,
		CertPEM:      resp.Cert,
		SerialNumber: resp.SerialNumber,
	})
	if err != nil {
		return nil, err
	}
	cert.KeyPEM = resp.Key
	return cert, nil
}

var commonName string

func init() {
	certsCmd.AddCommand(issueCertCmd)
	issueCertCmd.Flags().StringVarP(&caName, "ca-name", "n", "", "CA Name")
	issueCertCmd.Flags().StringVarP(&commonName, "common-name", "", "", "common name")
}
