// Package config loads the wgxdp YAML configuration from disk.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Config holds all server settings loaded from the YAML configuration file.
type Config struct {
	Name            string `yaml:"name"`
	ServerURL       string `yaml:"server_url"`
	WGEndpoint      string `yaml:"wg_endpoint"`
	WGSubnet        string `yaml:"wg_subnet"`
	WGInterfaceIP   string `yaml:"wg_interface_ip"`
	WGInterfaceName string `yaml:"wg_interface_name"`
	WGListenPort    int    `yaml:"wg_listen_port"`
	AuthHeader      string `yaml:"auth_header"`
	ListenAddr      string `yaml:"listen_addr"`
	WGKeyFile       string `yaml:"wg_key_file"`
	DBPath          string `yaml:"db_path"`
}

// New creates a Config by loading from the YAML file specified by the
// CONFIG_FILE environment variable, or /config/config.yaml by default.
func New() (*Config, error) {
	c := &Config{}
	if err := c.Load(); err != nil {
		return nil, err
	}

	return c, nil
}

// Load reads and parses the YAML configuration file into c.
func (c *Config) Load() error {
	configFile, configEnvExists := os.LookupEnv("CONFIG_FILE")
	if configEnvExists == false {
		configFile = "/config/config.yaml"
	}
	data, err := os.ReadFile(configFile)
	if errors.Is(err, os.ErrNotExist) {
		logrus.Errorf("Config file %s not found", configFile)
		return fmt.Errorf("config file %s not found", configFile)
	}
	if err != nil {
		return fmt.Errorf("could not read config file: %w", err)
	}

	return yaml.Unmarshal(data, c)
}
