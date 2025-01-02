package database

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/meetwithabhishek/peeki/internal"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const file string = "peeki.db"

const initSQL string = `
  CREATE TABLE IF NOT EXISTS cas (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS certs (
  id INTEGER NOT NULL PRIMARY KEY,
  ca_id INTEGER NOT NULL REFERENCES cas(id),
  name TEXT NOT NULL
  );
`

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
	Key  string
}

type Cert struct {
	gorm.Model
	CAID uint
	CA   CA
}
