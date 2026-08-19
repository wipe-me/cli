package password

import (
	"bytes"
	"strings"
	"testing"
)

func TestPresetsAndRequirements(t *testing.T) {
	for _, tc := range []struct{ name, alphabet string }{{"portable", Portable}, {"alnum", Alnum}, {"base58", Base58}, {"base64url", Base64URL}, {"hex", "0123456789abcdef"}, {"digits", "0123456789"}, {"letters", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"}} {
		got, err := GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 128)), Options{Length: 32, Preset: tc.name})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got) != 32 {
			t.Fatalf("%s length %d", tc.name, len(got))
		}
		for _, b := range got {
			if !strings.ContainsRune(tc.alphabet, rune(b)) {
				t.Fatalf("%s emitted %q", tc.name, b)
			}
		}
	}
}

func TestPortableGuaranteesClasses(t *testing.T) {
	got, err := GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7}, 128)), Options{Length: 32, Preset: "portable"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, class := range []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "-_=+.,:@%"} {
		if !strings.ContainsAny(s, class) {
			t.Fatalf("missing class %q in %q", class, s)
		}
	}
}
func TestBase58Exclusions(t *testing.T) {
	got, err := GenerateFrom(bytes.NewReader(bytes.Repeat([]byte{0, 1, 2, 3, 4, 5}, 128)), Options{Length: 64, Preset: "base58"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(got), "0OIl") {
		t.Fatalf("invalid base58 %q", got)
	}
}
func TestValidation(t *testing.T) {
	for _, o := range []Options{{Length: MinLength - 1, Preset: "portable"}, {Length: MaxLength + 1, Preset: "portable"}, {Length: 32, Preset: "unknown"}, {Length: 32, Alphabet: "AAB"}, {Length: 32, Alphabet: "A "}, {Length: 32, Preset: "hex", Alphabet: "AB"}} {
		if _, err := GenerateFrom(bytes.NewReader(make([]byte, 1024)), o); err == nil {
			t.Fatalf("accepted %#v", o)
		}
	}
}
func TestRejectionSamplingSkipsBiasedTail(t *testing.T) {
	got, err := GenerateFrom(bytes.NewReader(append(bytes.Repeat([]byte{255}, 20), bytes.Repeat([]byte{0}, 100)...)), Options{Length: 8, Alphabet: "ABC", NoRequireEach: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "AAAAAAAA" {
		t.Fatalf("got %q", got)
	}
}
