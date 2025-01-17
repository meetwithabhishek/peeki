package database

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/meetwithabhishek/peeki/internal"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const file string = "peeki.db"

var db *gorm.DB

func Initialize() error {
	var err error
	db, err = gorm.Open(sqlite.Open(internal.GetPlayPath(file)), &gorm.Config{})
	if err != nil {
		return err
	}

	err = db.AutoMigrate(&CA{}, &Cert{})
	if err != nil {
		return err
	}
	return nil
}

type CA struct {
	gorm.Model
	Name string `gorm:"unique"`
	Cert string
	Key  string `json:"-"`
}

func NewCA(ca CA) (*CA, error) {
	err := db.Create(&ca).Error
	if err != nil {
		return nil, err
	}

	return &ca, nil
}

func GetCA(name string) (*CA, error) {
	var c CA
	err := db.First(&c, &CA{Name: name}).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func ListCAs() ([]CA, error) {
	var cas []CA
	err := db.Find(&cas).Error
	if err != nil {
		return nil, err
	}
	return cas, nil
}

type Cert struct {
	gorm.Model
	SerialNumber string
	CertPEM      string
	KeyPEM       string `gorm:"-"`
	CAID         uint
	CA           CA `json:"-"`
}

func NewCert(cert Cert) (*Cert, error) {
	err := db.Create(&cert).Error
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func ListCerts() ([]Cert, error) {
	var cert []Cert
	err := db.Find(&cert).Error
	if err != nil {
		return nil, err
	}
	return cert, nil
}
