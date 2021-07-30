package state

import (
	"testing"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/mguentner/passwordless/test"
)

func TestInsertToken(t *testing.T) {
	config := test.DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	state := State{
		DB: db,
	}
	keys, err := state.AllKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Error("Expected the state to be empty")
	}
	err = state.InsertToken(config, "foo@bar.com", "1234")
	if err != nil {
		t.Fatal(err)
	}
	keys, err = state.AllKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Error("Expected the state to contain exactly one key")
	}
}

func TestTokenForIdentifier(t *testing.T) {
	config := test.DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	state := State{
		DB: db,
	}
	err = state.InsertToken(config, "foo@bar.com", "1234")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := state.TokensForIdentifier("foo@bar.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Fatal("Expected exactly one token")
	}
	if tokens[0] != "1234" {
		t.Fatalf("Expected %s got %s", "1234", tokens[0])
	}
	err = state.InsertToken(config, "foo@bar.com", "4321")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err = state.TokensForIdentifier("foo@bar.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatalf("Expected exactly two token, got %d", len(tokens))
	}
}

func TestInvalidateToken(t *testing.T) {
	config := test.DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	state := State{
		DB: db,
	}
	err = state.InsertToken(config, "foo@bar.com", "1234")
	if err != nil {
		t.Fatal(err)
	}
	err = state.InsertToken(config, "foo@bar.com", "1337")
	if err != nil {
		t.Fatal(err)
	}
	err = state.InsertToken(config, "foo@baz.net", "abcd")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := state.TokensForIdentifier("foo@bar.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatal("Expected exactly two tokens")
	}
	err = state.InvalidateToken("foo@bar.com", "doesnotexist")
	if err == nil {
		t.Fatal("Expected an error for an non existant token")
	}
	err = state.InvalidateToken("foo@bar.com", "1337")
	if err != nil {
		t.Fatalf("Unexpected error while invalidating a token, %v", err)
	}
	tokens, err = state.TokensForIdentifier("foo@bar.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Fatal("Expected exactly one token")
	}
}

// TODO write timeout test
