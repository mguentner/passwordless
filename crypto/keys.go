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
