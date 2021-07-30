package state

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	"github.com/mguentner/passwordless/config"
	myCrypto "github.com/mguentner/passwordless/crypto"
	"github.com/rs/zerolog/log"

	badger "github.com/dgraph-io/badger/v3"
)

type State struct {
	DB          *badger.DB
	RSAKeyPairs []myCrypto.PublicPrivateRSAKeyPair
}

type ZerologBadgerLogger struct {
	badger.Logger
}

func (zl ZerologBadgerLogger) Errorf(format string, v ...interface{}) {
	log.Error().Str("module", "badger").Msgf(format, v...)
}

func (zl ZerologBadgerLogger) Infof(format string, v ...interface{}) {
	log.Info().Str("module", "badger").Msgf(format, v...)
}

func (zl ZerologBadgerLogger) Warningf(format string, v ...interface{}) {
	log.Warn().Str("module", "badger").Msgf(format, v...)
}

func (zl ZerologBadgerLogger) Debugf(format string, v ...interface{}) {
	log.Debug().Str("module", "badger").Msgf(format, v...)
}

func NewState(config config.Config, rsaKeyPairs []myCrypto.PublicPrivateRSAKeyPair) (*State, error) {
	badgerOptions := badger.DefaultOptions(config.StatePath).WithLogger(ZerologBadgerLogger{})
	db, err := badger.Open(badgerOptions)
	if err != nil {
		return nil, err
	}
	return &State{
		DB:          db,
		RSAKeyPairs: rsaKeyPairs,
	}, nil
}

func EncodeIdentifier(identifier string) string {
	identifierSha256 := sha256.Sum256([]byte(identifier))
	return base64.StdEncoding.EncodeToString(identifierSha256[:])
}

func (s *State) TokensForIdentifier(identifier string) ([]string, error) {
	encodedIdentifier := EncodeIdentifier(identifier)
	tokens := []string{}
	err := s.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(encodedIdentifier)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				tokens = append(tokens, string(v[:]))
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return tokens, err
}

type TooManyTokensIssued struct{}

func (e *TooManyTokensIssued) Error() string {
	return "TooManyTokensIssued"
}

func (s *State) InsertToken(config config.Config, identifier string, token string) error {
	currentTimeStamp := time.Now().Unix()
	encodedIdentifier := EncodeIdentifier(identifier)
	nonce := rand.Int()
	key := fmt.Sprintf("%s-%d-%d", encodedIdentifier, currentTimeStamp, nonce)
	err := s.DB.Update(func(txn *badger.Txn) error {
		tokens := []string{}
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(encodedIdentifier)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				tokens = append(tokens, string(v[:]))
				return nil
			})
			if err != nil {
				return err
			}
		}
		if len(tokens) >= int(config.MaxLoginTokenCount) {
			return &TooManyTokensIssued{}
		}
		e := badger.NewEntry([]byte(key), []byte(token)).WithTTL(time.Second * time.Duration(config.LoginTokenLifeTimeSeconds))
		return txn.SetEntry(e)
	})
	return err
}

func keyForIdentifierTokenPair(txn *badger.Txn, identifier string, token string) ([]byte, error) {
	encodedIdentifier := EncodeIdentifier(identifier)
	it := txn.NewIterator(badger.DefaultIteratorOptions)
	defer it.Close()
	prefix := []byte(encodedIdentifier)
	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
		item := it.Item()
		key := []byte{}
		err := item.Value(func(v []byte) error {
			if string(v) == token {
				key = it.Item().Key()
				return nil
			}
			return nil
		})
		if err != nil {
			continue
		}
		if len(key) > 0 {
			return key, nil
		}
	}
	return []byte{}, nil
}

func (s *State) KeyForIdentifierTokenPair(identifier string, token string) ([]byte, error) {
	key := []byte{}
	err := s.DB.View(func(txn *badger.Txn) error {
		k, err := keyForIdentifierTokenPair(txn, identifier, token)
		if err != nil {
			return err
		}
		key = k
		return nil
	})
	return key, err
}

type NoSuchIdentifierTokenPair struct{}

func (e *NoSuchIdentifierTokenPair) Error() string {
	return "NoSuchIdentifierTokenPair"
}

func (s *State) InvalidateToken(identifier string, token string) error {
	err := s.DB.Update(func(txn *badger.Txn) error {
		key, err := keyForIdentifierTokenPair(txn, identifier, token)
		if err != nil {
			return err
		}
		if len(key) == 0 {
			return &NoSuchIdentifierTokenPair{}
		}
		return txn.Delete(key)
	})
	return err
}
