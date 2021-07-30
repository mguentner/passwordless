package token

import (
	"crypto/rand"
	"math/big"

	"github.com/mguentner/passwordless/config"
)

func generateRandomToken(length uint8, alphabet []rune) (string, error) {
	alphabetLength := big.NewInt(int64(len(alphabet)))
	token := []rune{}
	for i := 0; i < int(length); i++ {
		index, err := rand.Int(rand.Reader, alphabetLength)
		if err != nil {
			return "", nil
		}
		token = append(token, alphabet[index.Int64()])
	}
	return string(token), nil
}

type TokenGenerator interface {
	generate(length uint8) (string, error)
}

type NumericTokenGenerator struct {
}

func (n *NumericTokenGenerator) generate(length uint8) (string, error) {
	alphabet := []rune("0123456789")
	return generateRandomToken(length, alphabet)
}

type AlphaNumericTokenGenerator struct {
}

func (n *AlphaNumericTokenGenerator) generate(length uint8) (string, error) {
	alphabet := []rune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	return generateRandomToken(length, alphabet)
}

func GeneratorFromConfig(config config.Config) TokenGenerator {
	if config.TokenFormat == "numeric" {
		return &NumericTokenGenerator{}
	} else {
		return &AlphaNumericTokenGenerator{}
	}
}

func Generate(config config.Config) (string, error) {
	generator := GeneratorFromConfig(config)
	return generator.generate(uint8(config.TokenLength))
}
