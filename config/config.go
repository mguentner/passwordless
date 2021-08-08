package config

import (
	"errors"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type SMTPConfig struct {
	FromAddr string `yaml:"fromAddr"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
}

type Config struct {
	ListenPort uint16 `yaml:"listenPort"`
	// How long LoginTokens should be valid / stored
	LoginTokenLifeTimeSeconds uint64 `yaml:"loginTokenLifeTimeSeconds"`
	// How many LoginTokens can be generated before rejecting new
	// requests
	MaxLoginTokenCount uint16 `yaml:"maxLoginTokenCount"`
	// See SMTPConfig
	SMTP SMTPConfig `yaml:"smtp"`
	// Can either be `alpha` or `numeric`
	TokenFormat string `yaml:"tokenFormat"`
	TokenLength int    `yaml:"tokenLength"`
	// this will show up in emails
	ServiceName string `yaml:"serviceName"`
	// where the database is stored
	StatePath string `yaml:"statePath"`
	// where the signing keys are stored
	KeyPath string `yaml:"keyPath"`
	// make this short lived, e.g. 1 hour
	AccessTokenLifetimeSeconds uint64 `yaml:"accessTokenLifetimeSeconds"`
	// make this long lived, e.g. 3 days
	RefreshTokenLifetimeSeconds uint64 `yaml:"refreshTokenLifetimeSeconds"`
}

func (c Config) Validate() error {
	if c.ListenPort == 0 {
		return errors.New("Invalid listenPort")
	}
	if !(c.TokenFormat == "alpha" || c.TokenFormat == "numeric") {
		return errors.New("tokenFormat not `alpha` or `numeric`")
	}
	if len(c.StatePath) == 0 {
		return errors.New("StatePath needs to be filled")
	}
	if len(c.KeyPath) == 0 {
		return errors.New("keyPath needs to be filled")
	}
	if c.AccessTokenLifetimeSeconds == 0 {
		return errors.New("accessTokenLifetimeSeconds must be set")
	}
	if c.RefreshTokenLifetimeSeconds == 0 {
		return errors.New("refreshTokenLifetimeSeconds must be set")
	}
	return nil
}

func ReadConfigFromFile(path string) (*Config, error) {
	var config Config

	yml, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yml, &config)
	if err != nil {
		return nil, err
	}
	err = config.Validate()
	if err != nil {
		return &config, err
	}
	return &config, nil
}

type Configurable interface {
	GetConfig() *Config
}

type BasicConfig struct {
	Config
}

func (e BasicConfig) GetConfig() *Config {
	return &e.Config
}
