package test

import "github.com/mguentner/passwordless/config"

func DefaultConfig() config.Config {
	return config.Config{
		LoginTokenLifeTimeSeconds: 3600,
		MaxLoginTokenCount:        10,
		SMTP: config.SMTPConfig{
			FromAddr: "alice@example.com",
			User:     "alice",
			Password: "insecure",
			Host:     "example.com",
			Port:     25,
		},
		TokenFormat: "numeric",
		TokenLength: 8,
	}
}
