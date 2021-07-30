package token

import (
	"crypto/subtle"
)

func ConstantTimeCompare(a string, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)
	numRes := subtle.ConstantTimeCompare(aBytes, bBytes)
	return numRes == 1
}
