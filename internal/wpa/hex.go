package wpa

import (
	"encoding/hex"
	"errors"
	"strings"
)

// decodeHex accepts upper or lower case hexadecimal with optional separators
// and reports the decoded length so a truncated key cannot pass silently.
func decodeHex(value string) ([]byte, error) {
	cleaned := strings.NewReplacer(":", "", "-", "", " ", "").Replace(strings.TrimSpace(value))
	if cleaned == "" {
		return nil, errEmptyHex
	}
	if len(cleaned)%2 != 0 {
		return nil, errOddHexLength
	}
	return hex.DecodeString(cleaned)
}

var (
	errEmptyHex     = errors.New("no hexadecimal digits were supplied")
	errOddHexLength = errors.New("a hexadecimal key must have an even number of digits")
)
