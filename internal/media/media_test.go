package media

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectPNG(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgAH/CRW9WQAAAABJRU5ErkJggg==")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "misleading.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := Inspect(path, "picture.png", "")
	if err != nil {
		t.Fatal(err)
	}
	if file.Type != "image/png" || file.Kind != "image" || file.Width != 1 || file.Height != 1 {
		t.Fatalf("unexpected inspection: %#v", file)
	}
}

func TestInspectUsesExtensionAsFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sound.m4a")
	if err := os.WriteFile(path, []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := Inspect(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if file.Kind != "audio" {
		t.Fatalf("expected audio fallback, got %#v", file)
	}
}
