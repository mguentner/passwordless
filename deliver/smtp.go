package deliver

import (
	"fmt"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/mguentner/passwordless/config"
)

type SMTPAgent struct {
}

func (h SMTPAgent) Deliver(config config.Config, identifier string, subject string, body string) error {
	auth := sasl.NewPlainClient("", config.SMTP.User, config.SMTP.Password)
	to := []string{identifier}
	msg := strings.NewReader(
		fmt.Sprintf(
			"From: %s\r\n"+
				"To: %s\r\n"+
				"Subject: %s\r\n"+
				"\r\n"+
				"%s\r\n", config.SMTP.FromAddr, identifier, subject, body),
	)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%d", config.SMTP.Host, config.SMTP.Port),
		auth,
		config.SMTP.FromAddr,
		to,
		msg)
	return err
}
