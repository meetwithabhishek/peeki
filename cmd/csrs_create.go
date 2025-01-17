package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/ansel1/merry/v2"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/spf13/cobra"
)

// issueCertCmd represents the issue command
var createCSRCmd = &cobra.Command{
	Use:   "create",
	Short: "create CSR",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Step 1: Generate a private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return merry.Prepend(err, "failed to generate private key")
		}

		// Step 2: Create a CSR template
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

		// Step 3: Generate the CSR
		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
		if err != nil {
			return merry.Prepend(err, "failed to generate CSR")
		}

		// Step 4: Encode the CSR in PEM format
		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		// Encode the private key in PEM format
		privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return merry.Prepend(err, "failed to encode private key")
		}

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
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
