/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
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
	"github.com/meetwithabhishek/peeki/internal"
	"github.com/spf13/cobra"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"time"
)

func getCAsPath(elem ...string) string {
	return internal.GetPlayPath(append([]string{internal.CADir}, elem...)...)
}

func getCRLsPath(elem ...string) string {
	return internal.GetPlayPath(append([]string{internal.CRLDir}, elem...)...)
}

// casCmd represents the ca command
var casCmd = &cobra.Command{
	Use:   "cas",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var caName string

func init() {
	rootCmd.AddCommand(casCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// casCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	casCmd.Flags().StringVarP(&caName, "name", "n", "", "CA Name")
}

var testServerURL string
var testServerPaths map[string]http.HandlerFunc
var testServerLock sync.Mutex

func hostPath(path string, handlerFunc http.HandlerFunc) error {
	testServerLock.Lock()
	defer testServerLock.Unlock()

	if testServerURL == "" {
		testServerPaths = make(map[string]http.HandlerFunc)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testServerLock.Lock()
			defer testServerLock.Unlock()

			hf, found := testServerPaths[r.URL.Path]
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			hf.ServeHTTP(w, r)
		}))

		testServerURL = server.URL
	}

	if _, found := testServerPaths[path]; found {
		return merry.New("path already hosted")
	}

	testServerPaths[path] = handlerFunc
	return nil
}

func removeHostedPath(path string) {
	testServerLock.Lock()
	defer testServerLock.Unlock()
	delete(testServerPaths, path)
}

func formURL(path string) string {
	return testServerURL + path
}

func parseCRL(crlBytes []byte) (*x509.RevocationList, error) {
	derBytes := crlBytes
	block, _ := pem.Decode(crlBytes)
	if block != nil {
		derBytes = block.Bytes
	}

	revocationList, err := x509.ParseRevocationList(derBytes)
	if err != nil {
		return revocationList, merry.Wrap(err)
	}
	return revocationList, nil
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

// MustParseCertificateString certificate to x509.Certificate format
func MustParseCertificateString(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, merry.New("Invalid PEM data.")
	} else if block.Type != internal.CertificateType {
		return nil, merry.New("Invalid PEM type.")
	}

	cert, err := x509.ParseCertificate((block.Bytes))
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

	//err = c.createCRL(nil)
	//if err != nil {
	//	return nil, err
	//}
	//
	//err = c.hostCRL()
	//if err != nil {
	//	return nil, err
	//}

	return c, nil
}

func GetCASetup(caName string) (*CASetup, error) {
	key, err := os.ReadFile(getCAsPath(caName, internal.CAKey))
	if err != nil {
		return nil, err
	}

	cert, err := os.ReadFile(getCAsPath(caName, internal.CACrt))
	if err != nil {
		return nil, err
	}

	c := &CASetup{CAName: caName, CACert: string(cert), CAKey: string(key)}
	return c, nil
}

func issueCRL(caName string, revokedCertList []x509.RevocationListEntry) error {
	setup, err := GetCASetup(caName)
	if err != nil {
		return err
	}

	crl, err := createCRLInternal(setup.CACert, setup.CAKey, revokedCertList)
	if err != nil {
		return err
	}

	err = internal.WriteToFile(getCRLsPath(caName+".crl"), crl)
	if err != nil {
		return err
	}
	return nil
}

// createCRL creates CRL
func (c *CASetup) createCRL(revokedCertList []x509.RevocationListEntry) error {
	crl, err := createCRLInternal(c.CACert, c.CAKey, revokedCertList)
	if err != nil {
		return err
	}

	c.CRL = crl

	return nil
}

func (c *CASetup) hostCRL() error {
	path := "/" + gofakeit.Noun()

	err := hostPath(path, func(w http.ResponseWriter, r *http.Request) {
		c.CRLRouteHits++
		w.WriteHeader(http.StatusOK)
		w.Write(c.CRL)
	})
	if err != nil {
		return err
	}

	c.CRLURL = formURL(path)

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

	parsedCert, err := MustParseCertificateString(caCert)
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
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
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
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return createCAResp{CertPem: caPEM.String(), KeyPem: caPrivKeyPEM.String()}, nil
}

type IssueCertResp struct {
	Cert string
	Key  string
}

func issueCertStandalone(caName string) (IssueCertResp, error) {
	setup, err := GetCASetup(caName)
	if err != nil {
		return IssueCertResp{}, err
	}
	return setup.issueCert()
}

func getCRLURL(caName string) (string, error) {
	joinPath, err := url.JoinPath("http://"+internal.GlobalConfig.IP, "crls", caName+".crl")
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
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
			CommonName:    gofakeit.Noun(),
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

	ca, err := MustParseCertificateString(c.CACert)
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
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return IssueCertResp{Cert: certPEM.String(), Key: certPrivKeyPEM.String()}, nil
}

func (c *CASetup) revokeCert(certPEM string) error {
	cert, err := MustParseCertificateString(certPEM)
	if err != nil {
		return err
	}

	list := []x509.RevocationListEntry{{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now(),
	}}

	err = c.createCRL(list)
	if err != nil {
		return err
	}

	return nil
}
