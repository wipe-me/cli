package base58

import (
	"bytes"
	"testing"
)

func TestRandomStringRejectsBiasedBytes(t *testing.T) {
	random := bytes.NewReader(append(bytes.Repeat([]byte{255}, 40), bytes.Repeat([]byte{0}, 40)...))
	got, err := RandomString(random, 16)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1111111111111111" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeAndGroup(t *testing.T) {
	const canonical = "7YWHMfk9JCB7P4eG"
	display := Group(canonical, 4)
	if display != "7YWH-Mfk9-JCB7-P4eG" {
		t.Fatalf("unexpected display value %q", display)
	}
	got, err := Normalize(display, 16)
	if err != nil {
		t.Fatal(err)
	}
	if got != canonical {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeRejectsAmbiguousAlphabetCharacters(t *testing.T) {
	if _, err := Normalize("0000-0000-0000-0000", 16); err == nil {
		t.Fatal("expected invalid alphabet error")
	}
}
