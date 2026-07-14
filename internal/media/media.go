// Package media inspects attachments without trusting their filename extension.
package media

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// File describes a local attachment. Path is never serialized into an envelope.
type File struct {
	Path   string
	Name   string
	Type   string
	Kind   string
	Size   int64
	Width  int
	Height int
}

// Inspect identifies a regular file using its content, with the extension only
// as a fallback when sniffing returns application/octet-stream.
func Inspect(path, nameOverride, typeOverride string) (File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return File{}, fmt.Errorf("inspect %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("attachment %q is not a regular file", path)
	}

	handle, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("open %q: %w", path, err)
	}
	defer handle.Close()

	name := nameOverride
	if name == "" {
		name = filepath.Base(path)
	}
	contentType := typeOverride
	if contentType == "" {
		contentType, err = detectType(handle, name)
		if err != nil {
			return File{}, err
		}
	}

	result := File{
		Path: path,
		Name: name,
		Type: contentType,
		Kind: kind(contentType),
		Size: info.Size(),
	}
	if result.Kind == "image" {
		if _, err := handle.Seek(0, io.SeekStart); err == nil {
			if config, _, decodeErr := image.DecodeConfig(handle); decodeErr == nil {
				result.Width = config.Width
				result.Height = config.Height
			}
		}
	}
	return result, nil
}

func detectType(reader io.ReadSeeker, name string) (string, error) {
	first := make([]byte, 512)
	n, err := reader.Read(first)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("inspect attachment content: %w", err)
	}
	detected := http.DetectContentType(first[:n])
	if detected == "application/octet-stream" {
		if byExtension := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); byExtension != "" {
			detected = byExtension
		}
	}
	if mediaType, _, parseErr := mime.ParseMediaType(detected); parseErr == nil {
		detected = mediaType
	}
	return detected, nil
}

func kind(contentType string) string {
	major, _, _ := strings.Cut(contentType, "/")
	switch major {
	case "image", "audio", "video", "text":
		return major
	default:
		return "file"
	}
}
