package template

import (
	"strings"
	"testing"
)

var testData = TemplateData{
	Service: "TestService",
	Token:   "abcd",
	IP:      "127.0.0.1",
}

func TestInvalidKey(t *testing.T) {
	_, err := EvaluateTemplate("invalid", "email", testData)
	if err == nil {
		t.Fatal("Expected the err to be not nil")
	}
}

func TestEmailEnglish(t *testing.T) {
	result, err := EvaluateTemplate("en", "email", testData)
	if err != nil {
		t.Fatalf("Expected err to be nil: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("Expected result to be non-empty")
	}
	if !strings.Contains(result, "TestService") {
		t.Fatal("Expected the result to contain `TestService`")
	}
	if !strings.Contains(result, "abcd") {
		t.Fatal("Expected the result to contain `abcd`")
	}
	if !strings.Contains(result, "127.0.0.1") {
		t.Fatal("Expected the result to contain `127.0.0.1`")
	}
}

func TestEmailEnglishSubject(t *testing.T) {
	result, err := EvaluateTemplate("en", "email-subject", testData)
	if err != nil {
		t.Fatalf("Expected err to be nil: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("Expected result to be non-empty")
	}
}
