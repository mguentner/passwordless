package template

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
)

type TemplateData struct {
	Service string
	Token   string
	IP      string
}

var templates = map[string]string{
	"en:email": `Hi,

your login Token is "{{.Token}}".

Login IP: {{.IP}}

Thanks,

{{.Service}}
`,
	"en:email-subject": "[{{.Service}}] - {{.Token}} is your login token.",
}

func EvaluateTemplate(lang string, id string, data TemplateData) (string, error) {
	key := fmt.Sprintf("%s:%s", lang, id)
	textTemplate, ok := templates[key]
	if !ok {
		return "", errors.New("No such template")
	}
	parsedTemplate, err := template.New(key).Parse(textTemplate)
	if err != nil {
		return "", err
	}
	sBuilder := &strings.Builder{}
	err = parsedTemplate.Execute(sBuilder, data)
	if err != nil {
		return "", err
	}
	return sBuilder.String(), nil
}
