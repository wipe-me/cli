// Package base58 implements the Base58BTC alphabet used by wipe.me links.
package base58

import (
	"fmt"
	"io"
	"strings"
)

const Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var alphabetIndex = func() [256]int16 {
	var table [256]int16
	for i := range table {
		table[i] = -1
	}
	for i := range Alphabet {
		table[Alphabet[i]] = int16(i)
	}
	return table
}()

// RandomString returns a uniformly distributed Base58BTC string.
func RandomString(random io.Reader, length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("base58 length must be positive")
	}

	// 232 is the largest multiple of 58 that fits in one byte. Rejecting bytes
	// at or above it avoids modulo bias.
	result := make([]byte, length)
	buffer := make([]byte, length*2)
	for written := 0; written < length; {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", fmt.Errorf("read randomness: %w", err)
		}
		for _, value := range buffer {
			if value >= 232 {
				continue
			}
			result[written] = Alphabet[int(value)%len(Alphabet)]
			written++
			if written == length {
				break
			}
		}
	}
	return string(result), nil
}

// Normalize removes presentation separators and validates Base58BTC text.
func Normalize(value string, expectedLength int) (string, error) {
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, " ", "")
	if len(value) != expectedLength {
		return "", fmt.Errorf("expected %d Base58 characters, got %d", expectedLength, len(value))
	}
	for i := range value {
		if alphabetIndex[value[i]] < 0 {
			return "", fmt.Errorf("invalid Base58 character %q", value[i])
		}
	}
	return value, nil
}

// Group inserts dashes every size characters.
func Group(value string, size int) string {
	if size < 1 || len(value) <= size {
		return value
	}
	var result strings.Builder
	result.Grow(len(value) + len(value)/size)
	for i := range value {
		if i > 0 && i%size == 0 {
			result.WriteByte('-')
		}
		result.WriteByte(value[i])
	}
	return result.String()
}

// Valid reports whether value is canonical Base58BTC of the requested length.
func Valid(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := range value {
		if alphabetIndex[value[i]] < 0 {
			return false
		}
	}
	return true
}
