package cmd

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/ansel1/merry/v2"
	"github.com/brianvoe/gofakeit/v7"
	"github.com/meetwithabhishek/peeki/database"
	"github.com/meetwithabhishek/peeki/internal"
	"github.com/spf13/cobra"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func getCRLsPath(elem ...string) string {
	return internal.GetPlayPath(append([]string{internal.CRLDir}, elem...)...)
}

// casCmd represents the ca command
var casCmd = &cobra.Command{
	Use:   "cas",
	Short: "manage certification authorities",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	rootCmd.AddCommand(casCmd)
}

var testServerURL string
var testServerPaths map[string]http.HandlerFunc
var testServerLock sync.Mutex

func removeHostedPath(path string) {
	testServerLock.Lock()
	defer testServerLock.Unlock()
	delete(testServerPaths, path)
}

func parseRSAKey(keyPem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPem))
	if block == nil {
		return nil, merry.New("Invalid PEM data.")
	} else if block.Type != internal.KeyAlgoTypeRSA {
		return nil, merry.New("Invalid PEM type.")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, merry.Wrap(err, merry.WithUserMessage("failed to parse private key"))
	}

	return privKey, nil
}

// parseCertificateString certificate to x509.Certificate format
func parseCertificateString(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, merry.New("Invalid PEM data")
	} else if block.Type != internal.CertificateType {
		return nil, merry.New("Invalid PEM type")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

type CASetup struct {
	CAName       string
	CACert       string
	CAKey        string
	CRL          []byte
	CRLURL       string
	CRLRouteHits int
}

func NewCASetup() (*CASetup, error) {
	ca, err := createCA()
	if err != nil {
		return nil, err
	}

	c := &CASetup{CACert: ca.CertPem, CAKey: ca.KeyPem}

	return c, nil
}

func issueCRL(caName string, revokedCertList []x509.RevocationListEntry) error {
	ca, err := database.GetCA(caName)
	if err != nil {
		return err
	}

	crl, err := createCRLInternal(ca.Cert, ca.Key, revokedCertList)
	if err != nil {
		return err
	}

	err = internal.WriteToFile(getCRLsPath(caName+".crl"), crl)
	if err != nil {
		return err
	}
	return nil
}

func (c *CASetup) GetCRLURL() string {
	return c.CRLURL
}

func (c *CASetup) GetCRLBytes() []byte {
	return c.CRL
}

func (c *CASetup) Remove() {
	parse, err := url.Parse(c.CRLURL)
	if err != nil {
		return
	}
	removeHostedPath(parse.Path)
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, err
	}
	// x509.CreateCertificate also uses sha1 to calculate the same
	// nolint:gosec //creating hash for subject key id
	hash := sha1.Sum(info.SubjectPublicKey.Bytes)
	return hash[:], nil
}

func createCRLInternal(caCert string, caKey string, revokedCertList []x509.RevocationListEntry) ([]byte, error) {

	var err error
	var privKey crypto.Signer
	var signAlgo x509.SignatureAlgorithm
	var template *x509.RevocationList

	parsedCert, err := parseCertificateString(caCert)
	if err != nil {
		return nil, err
	}

	privKey, err = parseRSAKey(caKey)
	if err != nil {
		return nil, err
	}

	template = &x509.RevocationList{
		SignatureAlgorithm:        signAlgo,
		Number:                    big.NewInt(100),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(time.Hour * 720), // 30 days
		RevokedCertificateEntries: revokedCertList,
	}

	// if KeyUsage is not set, create a temporary spoofed cert for crl sign
	// this will be true in case of Certs migrated from KS classic
	if (parsedCert.KeyUsage & x509.KeyUsageCRLSign) == 0 {
		parsedCert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		parsedCert.BasicConstraintsValid = true
	}

	if len(parsedCert.SubjectKeyId) == 0 {
		parsedCert.SubjectKeyId, err = generateSubjectKeyID(parsedCert.PublicKey)
		if err != nil {
			return nil, merry.Prepend(err, "failed to create subject key id")
		}
	}

	crl, err := x509.CreateRevocationList(rand.Reader, template, parsedCert, privKey)
	if err != nil {
		return nil, merry.Prependf(err, "CreateRevocationList failed unexpectedly")
	}

	// CRL pem Block
	crlPemBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	}

	var crlBuffer bytes.Buffer
	err = pem.Encode(&crlBuffer, crlPemBlock)
	if err != nil {
		return nil, merry.Prependf(err, "CRL Encode failed")
	}

	return crlBuffer.Bytes(), nil
}

type createCAResp struct {
	CertPem string
	KeyPem  string
}

func createCA() (c createCAResp, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return c, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return c, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return c, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return c, err
	}

	return createCAResp{CertPem: caPEM.String(), KeyPem: caPrivKeyPEM.String()}, nil
}
