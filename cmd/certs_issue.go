package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/meetwithabhishek/peeki/database"
	"github.com/meetwithabhishek/peeki/internal"
	"github.com/spf13/cobra"
	"math/big"
	"net"
	"net/url"
	"time"
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

var commonName string

func init() {
	certsCmd.AddCommand(issueCertCmd)
	issueCertCmd.Flags().StringVarP(&caName, "ca-name", "n", "", "CA Name")
	issueCertCmd.Flags().StringVarP(&commonName, "common-name", "", "", "common name")
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

type IssueCertReq struct {
	caName     string
	caCert     string
	caKey      string
	commonName string
}

type IssueCertResp struct {
	Cert         string
	Key          string
	SerialNumber string
}

func issueCertStandalone(params IssueCertReq) (r *IssueCertResp, err error) {
	crlurl, err := getCRLURL(params.caName)
	if err != nil {
		return r, err
	}

	commonName := params.commonName
	if commonName == "" {
		commonName = gofakeit.Noun()
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(gofakeit.Int64()),
		Subject: pkix.Name{
			CommonName:    commonName,
			Organization:  []string{gofakeit.Company()},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{gofakeit.Address().City},
			StreetAddress: []string{gofakeit.Address().Street},
			PostalCode:    []string{gofakeit.Address().Zip},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{crlurl},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return r, err
	}

	ca, err := parseCertificateString(params.caCert)
	if err != nil {
		return r, err
	}

	caPrivKey, err := parseRSAKey(params.caKey)
	if err != nil {
		return r, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return r, err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, err
	}

	return &IssueCertResp{Cert: certPEM.String(), Key: certPrivKeyPEM.String(), SerialNumber: cert.SerialNumber.String()}, nil
}

func getCRLURL(caName string) (string, error) {
	joinPath, err := url.JoinPath("http://"+internal.GlobalConfig.SocketAddress, "crls", caName+".crl")
	if err != nil {
		return "", err
	}
	return joinPath, nil
}

func (c *CASetup) issueCert() (r IssueCertResp, err error) {
	crlurl, err := getCRLURL(c.CAName)
	if err != nil {
		return IssueCertResp{}, err
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(gofakeit.Int64()),
		Subject: pkix.Name{
			CommonName:    gofakeit.Noun(),
			Organization:  []string{gofakeit.Company()},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{gofakeit.Address().City},
			StreetAddress: []string{gofakeit.Address().Street},
			PostalCode:    []string{gofakeit.Address().Zip},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{crlurl},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return r, err
	}

	ca, err := parseCertificateString(c.CACert)
	if err != nil {
		return r, err
	}

	caPrivKey, err := parseRSAKey(c.CAKey)
	if err != nil {
		return r, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return r, err
	}

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return r, err
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return r, err
	}

	return IssueCertResp{Cert: certPEM.String(), Key: certPrivKeyPEM.String()}, nil
}
