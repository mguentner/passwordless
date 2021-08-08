package crypto

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/mguentner/passwordless/config"

	"github.com/rs/zerolog/log"
)

type PublicPrivateRSAKeyPair struct {
	ValidFrom    int64
	PrivateKey   *rsa.PrivateKey
	PublicKeyPEM string
	PublicKey    *rsa.PublicKey
}

type ByValidFrom []PublicPrivateRSAKeyPair

func (v ByValidFrom) Len() int           { return len(v) }
func (v ByValidFrom) Swap(i, j int)      { v[i], v[j] = v[j], v[i] }
func (v ByValidFrom) Less(i, j int) bool { return v[i].ValidFrom < v[j].ValidFrom }

func ReadRSAKeysFromPath(path string) ([]PublicPrivateRSAKeyPair, error) {
	result := []PublicPrivateRSAKeyPair{}
	fileInfos, err := ioutil.ReadDir(path)
	if err != nil {
		return result, err
	}
	regex, err := regexp.Compile("^([0-9]*).key$")
	if err != nil {
		return result, err
	}
	for _, fileinfo := range fileInfos {
		if fileinfo.IsDir() {
			continue
		}
		matched := regex.FindAllStringSubmatch(fileinfo.Name(), -1)
		if len(matched) != 1 {
			continue
		}
		privateKeyFilePath := filepath.Join(path, fileinfo.Name())
		publicKeyFileName := fmt.Sprintf("%s.pub", matched[0][1])
		publicKeyFilePath := filepath.Join(path, publicKeyFileName)
		validFrom, err := strconv.ParseInt(matched[0][1], 10, 64)
		if err != nil {
			log.Warn().Msgf("Invalid timestamp: %v", err)
			continue
		}
		privateKeyData, err := ioutil.ReadFile(privateKeyFilePath)
		if err != nil {
			log.Warn().Msgf("Could not open private key: %v", err)
			continue
		}
		publicKeyData, err := ioutil.ReadFile(publicKeyFilePath)
		if err != nil {
			log.Warn().Msgf("Could not open public key: %v", err)
			continue
		}
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
		if err != nil {
			log.Warn().Msgf("Could not parse RSA private key: %v", err)
			continue
		}
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
		if err != nil {
			log.Warn().Msgf("Could not parse RSA public key: %v", err)
			continue
		}
		result = append(result, PublicPrivateRSAKeyPair{
			ValidFrom:    validFrom,
			PublicKey:    publicKey,
			PublicKeyPEM: string(publicKeyData),
			PrivateKey:   privateKey,
		})
	}
	return result, nil
}

func GetKeyForTime(keyPairs []PublicPrivateRSAKeyPair, time time.Time) *PublicPrivateRSAKeyPair {
	unixTime := time.Unix()
	sort.Sort(sort.Reverse(ByValidFrom(keyPairs)))
	for _, keyPair := range keyPairs {
		if keyPair.ValidFrom < unixTime {
			return &keyPair
		}
	}
	return nil
}

func GetAllPublicKeys(keyPairs []PublicPrivateRSAKeyPair) []rsa.PublicKey {
	publicKeys := []rsa.PublicKey{}
	for _, keyPair := range keyPairs {
		publicKeys = append(publicKeys, *keyPair.PublicKey)
	}
	return publicKeys
}

type UserInfo struct {
	Identifier string
}

type DefaultClaims struct {
	*jwt.StandardClaims
	TokenType string
	UserInfo
}

func createToken(keyPairs []PublicPrivateRSAKeyPair, forTime time.Time, lifeTimeSeconds int64, tokenType string, userInfo UserInfo) (string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = &DefaultClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(lifeTimeSeconds)).Unix(),
		},
		tokenType,
		userInfo,
	}
	signingKey := GetKeyForTime(keyPairs, forTime)
	if signingKey == nil {
		return "", errors.New("Could not find a suitable signing key")
	}
	return t.SignedString(signingKey.PrivateKey)
}

func CreateAccessToken(config config.Config, keyPairs []PublicPrivateRSAKeyPair, identifier string) (string, error) {
	now := time.Now()
	return createToken(keyPairs, now, int64(config.AccessTokenLifetimeSeconds), "access", UserInfo{
		Identifier: identifier,
	})
}

func CreateRefreshToken(config config.Config, keyPairs []PublicPrivateRSAKeyPair, identifier string) (string, error) {
	now := time.Now()
	return createToken(keyPairs, now, int64(config.RefreshTokenLifetimeSeconds), "refresh", UserInfo{
		Identifier: identifier,
	})
}

type AllParseAttemptsFailed struct{}

func (e *AllParseAttemptsFailed) Error() string {
	return "AllParseAttemptsFailed"
}

type InvalidTokenFound struct{}

func (e *InvalidTokenFound) Error() string {
	return "InvalidTokenFound"
}

type TokenExpired struct{}

func (e *TokenExpired) Error() string {
	return "TokenExpired"
}

func validateToken(keyPairs []PublicPrivateRSAKeyPair, token string, expectedTokenType string) (*DefaultClaims, error) {
	for _, publicKey := range GetAllPublicKeys(keyPairs) {
		token, err := jwt.ParseWithClaims(token, &DefaultClaims{}, func(token *jwt.Token) (interface{}, error) {
			return &publicKey, nil
		})
		if err != nil {
			if validationErr, ok := err.(*jwt.ValidationError); ok {
				if validationErr.Errors&jwt.ValidationErrorExpired != 0 {
					return nil, &TokenExpired{}
				}
			}
			continue
		}
		claims := token.Claims.(*DefaultClaims)
		if claims.TokenType != expectedTokenType {
			return nil, &InvalidTokenFound{}
		}
		return claims, nil
	}
	return nil, &AllParseAttemptsFailed{}
}

func ValidateRefreshToken(keyPairs []PublicPrivateRSAKeyPair, token string) (*DefaultClaims, error) {
	return validateToken(keyPairs, token, "refresh")
}

func ValidateAccessToken(keyPairs []PublicPrivateRSAKeyPair, token string) (*DefaultClaims, error) {
	return validateToken(keyPairs, token, "access")
}

func KeyPairForTesting() []PublicPrivateRSAKeyPair {
	privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAofMH3ayoHeB4h1lTiP/t4ZOVQ6yHRNiUnsqzDidjZvs2X/JQ
5q2eHDlCFEJtNpmsojnOrN81W2neFlVDDJ3PFgOS/ErqcKlH88/pXj6fTKwrNHOl
Zxykw8RM72p5uAHKpxgJVS0LbcGm2KCk+PYRM2lcxyi5h3xme2ROgngBWyRVxg7c
0OjIk1cLBYo+fEWYGp54OuX0qpFK6scpC3S8Eof4y0VKyJ6Vc1Hhe/wlT7nJxOZI
Soyo1qCj3qW5oTpgQdEYt+32ZxkuCuAfUVMMhMFO7hjjHfuyof366D1DYFdewSNN
66ZJI9DNbUPgfFnl4VmRvznmQrN3GLkHHuhZywIDAQABAoIBAFr+aYIFG+TFlhM+
fnAwlKE1Qh3nF434PvFFpPuj5/cZ2UBpr0kdbgQfq+AkPqb6C4SPBHAfbiRxxIY5
29V/6bZNxc2Z7kXk53e3b0Ez4F+9MP1kqR/ZeT5B0pSG9+MKpqniGIRSLeS6dRus
j2UPJTUE00tXt37Hx/E2t+IYuXJSf/T3/7V0FiYAJIAzA64+4/R/b1lgTu8LdoC2
SnloYtL/TWF7gg+jQExYEiiL6qxzKAPqtGeZxoONjU8GDXixxDdCsuF3887bUAur
bZOIVEFEujGyf2u3pMpR9k32HYJ+pPsYFLUIngJeNOyDm/H2mmNIpIBKm4zI6zbZ
f7rAQQkCgYEA1vlCSAdFFfki3gdgm7DPDMXdRgdqZpRkAm75YFAo4Fg0JWzw8HAA
Mm1P306n6QLjao1LxhMe6Z1Ce/kOynqxLSYqSUjczYWgf+2fh63KsS/FXIfggtbY
Bw9htci6tk+3k216my24VL09Lc+66flt/zBIyEJBayHJ0Us5q1adTAUCgYEAwNs3
4FrLnOWllUexNg3RT3vp39VBVdkXoVhZY7RmlntDbD+S56JdfuI3KU57w5uZi0si
WFIRdL4+ic6qbn0E9LnXjtcLgXIjbue7Laj72tEbw4ZXZx/RP6W5Q2DtUbzeyNxP
fwfkNuJr1YubzNYJs+LNHbbYxCiQU3vN8SCXx48CgYAbembvgAZjpaHAUZ8Wp4X/
svbysZX3ILab3QWBOx3Od1fLBN7TTO2phHF2ML6juRvKjd8GpYEJCXHrGM28Meyd
wcgb7/VRS+hVEdGXbS6AcYO/rRqUftPEK0IpE0xSa2Qisxa96R0rr7i3N1tD9v8J
ZGmZN2bXQ81hNEVd0kdu5QKBgQCE8Jg711qz9LmHhbvqfuvh1pEI8n/vJY7ccYJs
8FYnNSDs5YXmlk3MwTM1DhzSYdgd5NTv/OJ7jwidBhEFyLg52kF0/Ve5C2zRbnvg
pbO2yp5Q0bI+K/iZ3yst/wqYZZFM9FD4SABQtROQSIRFVuWpUpYB/aC+1xdl9Nmp
dcYqkQKBgQCccewmQnqJv9r6ZKLQGlzFKKfzlJMva9xYTDwoEzg6s8yaFpSbewp4
2IHw6228eeDWDMh8Ge1ZQNIWf4+vWEvWKn2gyWZ+caJBfesN5GHy6XlFpGYdbQnC
/irCLnYcupzN/IDNIl45kJwpRssb1gugguDZv1h+3j52wWFSdAElEQ==
-----END RSA PRIVATE KEY-----`
	publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAofMH3ayoHeB4h1lTiP/t
4ZOVQ6yHRNiUnsqzDidjZvs2X/JQ5q2eHDlCFEJtNpmsojnOrN81W2neFlVDDJ3P
FgOS/ErqcKlH88/pXj6fTKwrNHOlZxykw8RM72p5uAHKpxgJVS0LbcGm2KCk+PYR
M2lcxyi5h3xme2ROgngBWyRVxg7c0OjIk1cLBYo+fEWYGp54OuX0qpFK6scpC3S8
Eof4y0VKyJ6Vc1Hhe/wlT7nJxOZISoyo1qCj3qW5oTpgQdEYt+32ZxkuCuAfUVMM
hMFO7hjjHfuyof366D1DYFdewSNN66ZJI9DNbUPgfFnl4VmRvznmQrN3GLkHHuhZ
ywIDAQAB
-----END PUBLIC KEY-----`
	privateKeyData, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	publicKeyData, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	return []PublicPrivateRSAKeyPair{
		{
			ValidFrom:    0,
			PrivateKey:   privateKeyData,
			PublicKeyPEM: publicKey,
			PublicKey:    publicKeyData,
		},
	}
}
