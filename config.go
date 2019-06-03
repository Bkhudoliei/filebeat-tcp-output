package tcpout

import (
	"github.com/elastic/beats/libbeat/outputs/codec"
	"github.com/pkg/errors"
	"os"
	"fmt"
)

type tcpoutConfig struct {
	Host string `config:"host"`
	Port int    `config:"port"`
	Codec codec.Config `config:"codec"`
	UseSSL bool `config:"usessl"`
	SSLCert string `config:"sslcert"`
	SSLKey string `config:"sslkey"`
}

var (
	defaultConfig = tcpoutConfig{
		Port: 5556,
	}
)

func (c *tcpoutConfig) Validate() error {
	if c.UseSSL == true {
		if _, err := os.Stat(c.SSLCert); os.IsNotExist(err) {
			return errors.New(fmt.Sprintf("Certificate %s not found", c.SSLCert))
		}
		if _, err := os.Stat(c.SSLKey); os.IsNotExist(err) {
			return errors.New(fmt.Sprintf("Key %s not found", c.SSLKey))
		}
	}
	return nil
}
