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
	SocketAddress string `json:"socket_address"`
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
	// helper task
	// create a sample config file, if it doesn't exists
	_, err := os.Stat(GetPlayPath(ConfigFileName))
	if err != nil {
		err := WriteToFile(GetPlayPath(ConfigFileName), []byte("{\"socket_address\": \"localhost:3000\"}"))
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
