package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/ansel1/merry/v2"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/spf13/cobra"
)

// createCSRCmd represents the create CSR command
var createCSRCmd = &cobra.Command{
	Use:   "create",
	Short: "create CSR",
	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return merry.Prepend(err, "failed to generate private key")
		}

		subject := pkix.Name{
			CommonName:         commonName,
			Country:            []string{"IN"},
			Organization:       []string{gofakeit.Company()},
			OrganizationalUnit: []string{gofakeit.Noun()},
			Locality:           []string{gofakeit.Address().Street},
			Province:           []string{gofakeit.State()},
		}

		csrTemplate := x509.CertificateRequest{
			Subject: subject,
			DNSNames: []string{
				gofakeit.DomainName(),
			},
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
		if err != nil {
			return merry.Prepend(err, "failed to generate CSR")
		}

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return merry.Prepend(err, "failed to encode private key")
		}

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		return out(struct {
			CSR string `json:"csr"`
			Key string `json:"key"`
		}{string(csrPEM), string(privateKeyPEM)})
	},
}

func init() {
	csrsCmd.AddCommand(createCSRCmd)
	createStringFlag(createCSRCmd, &commonName, []string{"common-name", "cn"}, gofakeit.Noun(), "Common Name")
}

func createStringFlag(c *cobra.Command, v *string, name []string, defValue string, usage string) {
	for _, n := range name {
		c.Flags().StringVarP(v, n, "", defValue, usage)
	}
}
