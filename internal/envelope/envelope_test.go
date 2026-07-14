package envelope

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/wipe-me/cli/internal/media"
)

func TestProtocolVector(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := Write(&encrypted, "1K7mQ2xR8VpC", "hello from wipe.me", "7YWHMfk9JCB7P4eG", nil, WriteOptions{
		Random: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 128)),
		KDF:    KDFParams{MemoryKiB: 64, Iterations: 1, Threads: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "V0lQRU1FAAEAAABAAAAAAQHnsKMnU1nKpNxAqulNd67mWzZk7bpqURo688A/rz//5yoqKioqKioqKioqKgAAAFGF2i2ruMvJ9UjmwemeGqhZOX5P5nWTzeB2MoO3WBXtd289DLl7Fhg5cwD6uAM2aXUheTLm4ZEafRJf3u2FzOgPgEZCOTCfWPkJio/RXkBxctkA"
	if got := base64.StdEncoding.EncodeToString(encrypted.Bytes()); got != expected {
		t.Fatalf("protocol vector changed:\n%s", got)
	}
}

func TestRoundTripMessageAndAttachment(t *testing.T) {
	data := bytes.Repeat([]byte("wipe.me\n"), 700000)
	path := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := media.Inspect(path, "renamed.txt", "")
	if err != nil {
		t.Fatal(err)
	}

	var encrypted bytes.Buffer
	secret := "7YWHMfk9JCB7P4eG"
	messageID := "1K7mQ2xR8VpC"
	result, err := Write(&encrypted, messageID, "private message", secret, []media.File{file}, WriteOptions{
		Random: bytes.NewReader(bytes.Repeat([]byte{42}, 256)),
		KDF:    KDFParams{MemoryKiB: 64, Iterations: 1, Threads: 1},
	})
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Read(bytes.NewReader(encrypted.Bytes()), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.Manifest.Message != "private message" {
		t.Fatalf("unexpected message %q", decrypted.Manifest.Message)
	}
	if len(decrypted.Attachments) != 1 || !bytes.Equal(decrypted.Attachments[0].Data, data) {
		t.Fatal("attachment did not round trip")
	}
	if decrypted.Attachments[0].Metadata.Name != "renamed.txt" || decrypted.Attachments[0].Metadata.Kind != "text" {
		t.Fatalf("unexpected metadata %#v", decrypted.Attachments[0].Metadata)
	}
	if bytes.Equal(result.DeletionKey[:], make([]byte, 32)) {
		t.Fatal("deletion key was not derived")
	}
}

func TestWrongSecretFails(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := Write(&encrypted, "1K7mQ2xR8VpC", "private", "7YWHMfk9JCB7P4eG", nil, WriteOptions{
		Random: bytes.NewReader(bytes.Repeat([]byte{7}, 128)),
		KDF:    KDFParams{MemoryKiB: 64, Iterations: 1, Threads: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(encrypted.Bytes()), "1K7mQ2xR8VpC", "8YWHMfk9JCB7P4eG"); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestTamperingFails(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := Write(&encrypted, "1K7mQ2xR8VpC", "private", "7YWHMfk9JCB7P4eG", nil, WriteOptions{
		Random: bytes.NewReader(bytes.Repeat([]byte{9}, 128)),
		KDF:    KDFParams{MemoryKiB: 64, Iterations: 1, Threads: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := encrypted.Bytes()
	data[len(data)-2] ^= 1
	if _, err := Read(bytes.NewReader(data), "1K7mQ2xR8VpC", "7YWHMfk9JCB7P4eG"); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestDeletionKeyCanBeReconstructedFromLinkCapabilities(t *testing.T) {
	messageID := "1K7mQ2xR8VpC"
	secret := "7YWHMfk9JCB7P4eG"
	var encrypted bytes.Buffer
	created, err := Write(&encrypted, messageID, "private", secret, nil, WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := DeriveDeletionKey(messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if created.DeletionKey != reconstructed {
		t.Fatal("reconstructed deletion key differs from creation key")
	}
}
