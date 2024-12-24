package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

var GlobalConfig *Config

type Config struct {
	IP string `json:"ip"`
}

func NewConfig() *Config {
	c := &Config{}

	contents, err := os.ReadFile(GetPlayPath(ConfigFileName))
	if err != nil {
		return nil
	}

	err = json.Unmarshal(contents, c)
	if err != nil {
		return nil
	}

	return c
}

func init() {
	_, err := os.Stat(GetPlayPath(ConfigFileName))
	if err != nil {
		err := WriteToFile(GetPlayPath(ConfigFileName), []byte("{}"))
		if err != nil {
			fmt.Println(err)
		}
	}
	GlobalConfig = NewConfig()
}

func GetPlayPath(elem ...string) string {
	h := os.Getenv("HOME")
	pl := path.Join(h, "."+ToolName)

	return path.Join(append([]string{pl}, elem...)...)
}

func WriteToFile(filename string, data []byte) error {
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}
	return nil
}
