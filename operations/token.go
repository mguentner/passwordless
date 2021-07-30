package operations

import (
	"github.com/mguentner/passwordless/config"
	"github.com/mguentner/passwordless/deliver"
	"github.com/mguentner/passwordless/state"
	"github.com/mguentner/passwordless/template"
	"github.com/mguentner/passwordless/token"
)

func GenerateAndStoreAndDeliverTokenForIdentifier(config config.Config, state state.State, identifier string, requestingIP string) error {
	token, err := token.Generate(config)
	if err != nil {
		return err
	}
	err = state.InsertToken(config, identifier, token)
	if err != nil {
		return err
	}
	templateData := &template.TemplateData{
		Service: config.ServiceName,
		Token:   token,
		IP:      requestingIP,
	}
	body, err := template.EvaluateTemplate("en", "email", *templateData)
	if err != nil {
		return err
	}
	subject, err := template.EvaluateTemplate("en", "email-subject", *templateData)
	if err != nil {
		return err
	}
	agent, err := deliver.AgentForIdentifier(identifier)
	if err != nil {
		return err
	}
	err = agent.Deliver(config, identifier, subject, body)
	if err != nil {
		return err
	}
	return nil
}

func InvalidateToken(state state.State, identifier string, token string) error {
	return state.InvalidateToken(identifier, token)
}
