package password

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	DefaultLength = 32
	MinLength     = 8
	MaxLength     = 4096
	Portable      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+.,:@%"
	Alnum         = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	Base58        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	Base64URL     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

type Options struct {
	Length           int
	Preset, Alphabet string
	NoRequireEach    bool
}

func Generate(o Options) ([]byte, error) { return GenerateFrom(rand.Reader, o) }

func GenerateFrom(source io.Reader, o Options) ([]byte, error) {
	if o.Length == 0 {
		o.Length = DefaultLength
	}
	if o.Length < MinLength || o.Length > MaxLength {
		return nil, fmt.Errorf("password length must be between %d and %d", MinLength, MaxLength)
	}
	if o.Alphabet != "" && o.Preset != "" {
		return nil, fmt.Errorf("--chars and --alphabet cannot be used together")
	}
	alphabet, classes, err := resolve(o)
	if err != nil {
		return nil, err
	}
	if !o.NoRequireEach && len(classes) > o.Length {
		return nil, fmt.Errorf("password is too short for the selected character requirements")
	}
	out := make([]byte, o.Length)
	position := 0
	if !o.NoRequireEach {
		for _, class := range classes {
			out[position], err = pick(source, class)
			if err != nil {
				return nil, err
			}
			position++
		}
	}
	for position < len(out) {
		out[position], err = pick(source, alphabet)
		if err != nil {
			return nil, err
		}
		position++
	}
	for i := len(out) - 1; i > 0; i-- {
		j, e := index(source, i+1)
		if e != nil {
			return nil, e
		}
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func resolve(o Options) (string, []string, error) {
	if o.Alphabet != "" {
		if !utf8.ValidString(o.Alphabet) {
			return "", nil, fmt.Errorf("custom alphabet is invalid UTF-8")
		}
		seen := map[byte]bool{}
		for i := 0; i < len(o.Alphabet); i++ {
			b := o.Alphabet[i]
			if b < 33 || b > 126 {
				return "", nil, fmt.Errorf("custom alphabet must contain printable non-whitespace ASCII")
			}
			if seen[b] {
				return "", nil, fmt.Errorf("custom alphabet contains duplicate characters")
			}
			seen[b] = true
		}
		if len(seen) < 2 {
			return "", nil, fmt.Errorf("custom alphabet must contain at least two characters")
		}
		return o.Alphabet, nil, nil
	}
	p := o.Preset
	if p == "" {
		p = "portable"
	}
	switch p {
	case "portable":
		return Portable, []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "-_=+.,:@%"}, nil
	case "alnum":
		return Alnum, []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"}, nil
	case "base58":
		return Base58, nil, nil
	case "base64url":
		return Base64URL, nil, nil
	case "hex":
		return "0123456789abcdef", nil, nil
	case "digits":
		return "0123456789", nil, nil
	case "letters":
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"}, nil
	case "ascii":
		{
			var b strings.Builder
			for i := 33; i <= 126; i++ {
				b.WriteByte(byte(i))
			}
			return b.String(), nil, nil
		}
	default:
		return "", nil, fmt.Errorf("unknown character preset %q", p)
	}
}

func pick(r io.Reader, alphabet string) (byte, error) {
	i, e := index(r, len(alphabet))
	if e != nil {
		return 0, e
	}
	return alphabet[i], nil
}
func index(r io.Reader, n int) (int, error) {
	if n < 2 || n > 256 {
		return 0, fmt.Errorf("invalid alphabet size")
	}
	limit := 256 - (256 % n)
	var b [1]byte
	for {
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, fmt.Errorf("read secure randomness: %w", e)
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}
