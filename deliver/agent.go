package deliver

import (
	"errors"
	"net/mail"

	"github.com/mguentner/passwordless/config"
)

type DeliverAgent interface {
	Deliver(config config.Config, identifier string, subject string, body string) error
}

func AgentForIdentifier(identifier string) (DeliverAgent, error) {
	_, err := mail.ParseAddress(identifier)
	if err == nil {
		agent := SMTPAgent{}
		return &agent, nil
	}
	return nil, errors.New("Unknown identifier format")
}
