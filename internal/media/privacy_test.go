package media

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeJPEGKeepsPixelsAndColorData(t *testing.T) {
	scan := []byte{0x11, 0x22, 0xff, 0x00, 0x33, 0xff, 0xd9}
	source := append([]byte{0xff, 0xd8},
		jpegSegment(0xe0, []byte("JFIF"))...)
	source = append(source, jpegSegment(0xe1, []byte("Exif"))...)
	source = append(source, jpegSegment(0xe2, []byte("ICC"))...)
	source = append(source, jpegSegment(0xed, []byte("IPTC"))...)
	source = append(source, jpegSegment(0xfe, []byte("GPS"))...)
	source = append(source, jpegSegment(0xda, []byte{1, 2})...)
	source = append(source, scan...)

	result := stripJPEGMetadata(source)
	if !bytes.HasSuffix(result, scan) {
		t.Fatal("compressed pixel scan changed")
	}
	for _, retained := range [][]byte{[]byte("JFIF"), []byte("ICC")} {
		if !bytes.Contains(result, retained) {
			t.Fatalf("expected %q to be retained", retained)
		}
	}
	for _, removed := range [][]byte{[]byte("Exif"), []byte("IPTC"), []byte("GPS")} {
		if bytes.Contains(result, removed) {
			t.Fatalf("expected %q to be removed", removed)
		}
	}
}

func TestSanitizePNGKeepsPixelAnimationAndColorChunks(t *testing.T) {
	source := append([]byte(nil), pngSignature...)
	source = append(source, pngChunk("IHDR", make([]byte, 13))...)
	source = append(source, pngChunk("iCCP", []byte{1, 2, 3})...)
	source = append(source, pngChunk("acTL", []byte{1, 2})...)
	source = append(source, pngChunk("eXIf", []byte{4, 5, 6})...)
	source = append(source, pngChunk("tEXt", []byte{7, 8})...)
	source = append(source, pngChunk("iTXt", []byte{9})...)
	source = append(source, pngChunk("pHYs", []byte{10, 11})...)
	source = append(source, pngChunk("IDAT", []byte{12, 13, 14})...)
	source = append(source, pngChunk("IEND", nil)...)

	result := stripPNGMetadata(source)
	for _, retained := range [][]byte{[]byte("IHDR"), []byte("iCCP"), []byte("acTL"), []byte("IDAT"), []byte("IEND")} {
		if !bytes.Contains(result, retained) {
			t.Fatalf("expected %q to be retained", retained)
		}
	}
	for _, removed := range [][]byte{[]byte("eXIf"), []byte("tEXt"), []byte("iTXt"), []byte("pHYs")} {
		if bytes.Contains(result, removed) {
			t.Fatalf("expected %q to be removed", removed)
		}
	}
}

func TestSanitizeWebPKeepsPixelsAnimationAlphaAndColor(t *testing.T) {
	chunks := append([]byte(nil), webPChunk("VP8X", []byte{0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0})...)
	chunks = append(chunks, webPChunk("ICCP", []byte{1, 2})...)
	chunks = append(chunks, webPChunk("ANIM", []byte{3, 4})...)
	chunks = append(chunks, webPChunk("EXIF", []byte{5, 6})...)
	chunks = append(chunks, webPChunk("XMP ", []byte{7, 8})...)
	chunks = append(chunks, webPChunk("VP8 ", []byte{9, 10})...)
	source := make([]byte, 12)
	copy(source, "RIFF")
	binary.LittleEndian.PutUint32(source[4:8], uint32(4+len(chunks)))
	copy(source[8:], "WEBP")
	source = append(source, chunks...)

	result := stripWebPMetadata(source)
	for _, retained := range [][]byte{[]byte("VP8X"), []byte("ICCP"), []byte("ANIM"), []byte("VP8 ")} {
		if !bytes.Contains(result, retained) {
			t.Fatalf("expected %q to be retained", retained)
		}
	}
	for _, removed := range [][]byte{[]byte("EXIF"), []byte("XMP ")} {
		if bytes.Contains(result, removed) {
			t.Fatalf("expected %q to be removed", removed)
		}
	}
	if result[20]&0x0c != 0 {
		t.Fatal("VP8X EXIF/XMP flags were not cleared")
	}
	if result[20]&0x32 != 0x32 {
		t.Fatal("VP8X ICC, alpha, or animation flag changed")
	}
	if got, want := int(binary.LittleEndian.Uint32(result[4:8]))+8, len(result); got != want {
		t.Fatalf("RIFF length=%d, file length=%d", got, want)
	}
}

func TestSanitizeMP3KeepsAudioFrames(t *testing.T) {
	frames := []byte{0xff, 0xfb, 0x90, 0x64, 1, 2, 3, 4}
	source := append([]byte("ID3\x04\x00\x00\x00\x00\x00\x04"), []byte{9, 8, 7, 6}...)
	source = append(source, frames...)
	source = append(source, []byte("TAG")...)
	source = append(source, make([]byte, 125)...)

	if result := stripMP3Metadata(source); !bytes.Equal(result, frames) {
		t.Fatalf("audio frames changed: %x", result)
	}
}

func TestSanitizeMetadataStagesPrivateCopyAndLeavesOriginalUnchanged(t *testing.T) {
	source := append([]byte{0xff, 0xd8}, jpegSegment(0xe1, []byte("Exif GPS"))...)
	source = append(source, jpegSegment(0xda, []byte{1, 2})...)
	source = append(source, []byte{3, 4, 0xff, 0xd9}...)
	path := filepath.Join(t.TempDir(), "photo.jpg")
	if err := os.WriteFile(path, source, 0o644); err != nil {
		t.Fatal(err)
	}
	file := File{Path: path, Name: "photo.jpg", Type: "image/jpeg", Kind: "image", Size: int64(len(source))}

	privateFile, changed, cleanup, err := SanitizeMetadata(file)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !changed || privateFile.Path == path || privateFile.Name != file.Name {
		t.Fatalf("unexpected sanitized file: %#v changed=%v", privateFile, changed)
	}
	if original, err := os.ReadFile(path); err != nil || !bytes.Equal(original, source) {
		t.Fatalf("original changed: %x err=%v", original, err)
	}
	cleaned, err := os.ReadFile(privateFile.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cleaned, []byte("Exif")) || privateFile.Size != int64(len(cleaned)) {
		t.Fatalf("metadata remains or size is stale: %#v %x", privateFile, cleaned)
	}
	if info, err := os.Stat(privateFile.Path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary permissions: info=%v err=%v", info, err)
	}
	cleanup()
	if _, err := os.Stat(privateFile.Path); !os.IsNotExist(err) {
		t.Fatalf("temporary file was not removed: %v", err)
	}
}

func TestSanitizeMetadataLeavesUnsupportedFileByteForByte(t *testing.T) {
	path := filepath.Join(t.TempDir(), "document.pdf")
	source := []byte("%PDF private metadata")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	file := File{Path: path, Name: "document.pdf", Type: "application/pdf", Size: int64(len(source))}

	result, changed, cleanup, err := SanitizeMetadata(file)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if changed || result.Path != path {
		t.Fatalf("unsupported file changed: %#v changed=%v", result, changed)
	}
}

func TestMalformedSupportedFilesAreNotRewritten(t *testing.T) {
	tests := []struct {
		name string
		call func([]byte) []byte
		data []byte
	}{
		{"jpeg", stripJPEGMetadata, []byte{0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff}},
		{"png", stripPNGMetadata, append(append([]byte(nil), pngSignature...), []byte{0, 0, 0, 100, 'e', 'X', 'I', 'f'}...)},
		{"webp", stripWebPMetadata, []byte("RIFF\xff\xff\xff\xffWEBPbad-data")},
		{"mp3", stripMP3Metadata, []byte("ID3\x04\x00\x00\x7f\x7f\x7f\x7f")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if result := test.call(test.data); !bytes.Equal(result, test.data) {
				t.Fatalf("malformed input changed: %x", result)
			}
		})
	}
}

func jpegSegment(marker byte, payload []byte) []byte {
	result := []byte{0xff, marker, 0, 0}
	binary.BigEndian.PutUint16(result[2:4], uint16(len(payload)+2))
	return append(result, payload...)
}

func pngChunk(chunkType string, payload []byte) []byte {
	result := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint32(result[:4], uint32(len(payload)))
	copy(result[4:8], chunkType)
	copy(result[8:], payload)
	return result
}

func webPChunk(chunkType string, payload []byte) []byte {
	result := make([]byte, 8+len(payload)+len(payload)%2)
	copy(result[:4], chunkType)
	binary.LittleEndian.PutUint32(result[4:8], uint32(len(payload)))
	copy(result[8:], payload)
	return result
}
