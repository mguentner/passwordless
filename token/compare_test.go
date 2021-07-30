package token

import (
	"testing"
)

func TestConstantTimeCompare(t *testing.T) {
	testSet := []struct {
		a        string
		b        string
		expected bool
	}{
		{
			a:        "not",
			b:        "equal",
			expected: false,
		},
		{
			a:        "equal",
			b:        "equal",
			expected: true,
		},
		{
			a:        "",
			b:        "",
			expected: true,
		},
		{
			a:        "1",
			b:        "",
			expected: false,
		},
	}
	for _, test := range testSet {
		res := ConstantTimeCompare(test.a, test.b)
		if res != test.expected {
			t.Errorf("Expected %t for a: %s, b: %s but got %t", test.expected, test.a, test.b, res)
		}
	}
}
