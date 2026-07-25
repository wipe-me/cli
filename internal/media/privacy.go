package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"mime"
	"os"
	"strings"
)

var pngSignature = []byte{137, 80, 78, 71, 13, 10, 26, 10}

// SanitizeMetadata removes supported private metadata into a mode-0600
// temporary copy. The source file is never modified. Unsupported files and
// supported files that need no changes are returned as-is.
func SanitizeMetadata(file File) (File, bool, func(), error) {
	sanitizer := metadataSanitizer(file.Type, file.Name)
	if sanitizer == nil {
		return file, false, func() {}, nil
	}

	original, err := os.ReadFile(file.Path)
	if err != nil {
		return File{}, false, nil, fmt.Errorf("read attachment %q for metadata cleanup: %w", file.Path, err)
	}
	cleaned := sanitizer(original)
	if bytes.Equal(cleaned, original) {
		return file, false, func() {}, nil
	}

	temporary, err := os.CreateTemp("", "wipeme-sanitized-*")
	if err != nil {
		return File{}, false, nil, fmt.Errorf("stage sanitized attachment %q: %w", file.Path, err)
	}
	path := temporary.Name()
	cleanup := func() { _ = os.Remove(path) }
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			cleanup()
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return File{}, false, nil, fmt.Errorf("protect sanitized attachment %q: %w", file.Path, err)
	}
	if _, err := temporary.Write(cleaned); err != nil {
		return File{}, false, nil, fmt.Errorf("stage sanitized attachment %q: %w", file.Path, err)
	}
	if err := temporary.Close(); err != nil {
		return File{}, false, nil, fmt.Errorf("stage sanitized attachment %q: %w", file.Path, err)
	}

	result := file
	result.Path = path
	result.Size = int64(len(cleaned))
	complete = true
	return result, true, cleanup, nil
}

type sanitizer func([]byte) []byte

func metadataSanitizer(contentType, name string) sanitizer {
	if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
		contentType = parsed
	}
	contentType = strings.ToLower(contentType)
	name = strings.ToLower(name)
	switch {
	case contentType == "image/jpeg" || strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg"):
		return stripJPEGMetadata
	case contentType == "image/png" || strings.HasSuffix(name, ".png"):
		return stripPNGMetadata
	case contentType == "image/webp" || strings.HasSuffix(name, ".webp"):
		return stripWebPMetadata
	case contentType == "audio/mpeg" || strings.HasSuffix(name, ".mp3"):
		return stripMP3Metadata
	default:
		return nil
	}
}

func stripJPEGMetadata(input []byte) []byte {
	if len(input) < 4 || input[0] != 0xff || input[1] != 0xd8 {
		return input
	}
	var output bytes.Buffer
	output.Grow(len(input))
	output.Write(input[:2])
	offset := 2
	foundScan := false

	for offset < len(input) {
		markerStart := offset
		if input[offset] != 0xff {
			return input
		}
		for offset < len(input) && input[offset] == 0xff {
			offset++
		}
		if offset >= len(input) {
			return input
		}
		marker := input[offset]
		offset++

		if marker == 0xda {
			if offset+2 > len(input) {
				return input
			}
			segmentLength := int(binary.BigEndian.Uint16(input[offset : offset+2]))
			if segmentLength < 2 || offset+segmentLength > len(input) {
				return input
			}
			output.Write(input[markerStart:])
			foundScan = true
			break
		}
		if marker == 0xd9 {
			output.Write(input[markerStart:offset])
			break
		}
		if marker == 0x01 || marker >= 0xd0 && marker <= 0xd7 {
			output.Write(input[markerStart:offset])
			continue
		}
		if offset+2 > len(input) {
			return input
		}
		segmentLength := int(binary.BigEndian.Uint16(input[offset : offset+2]))
		if segmentLength < 2 || offset+segmentLength > len(input) {
			return input
		}
		segmentEnd := offset + segmentLength
		if marker != 0xe1 && marker != 0xed && marker != 0xfe {
			output.Write(input[markerStart:segmentEnd])
		}
		offset = segmentEnd
	}
	if !foundScan && offset < len(input) {
		return input
	}
	return output.Bytes()
}

func stripPNGMetadata(input []byte) []byte {
	if len(input) < len(pngSignature) || !bytes.Equal(input[:8], pngSignature) {
		return input
	}
	var output bytes.Buffer
	output.Grow(len(input))
	output.Write(input[:8])
	offset := 8
	foundEnd := false

	for offset+12 <= len(input) {
		chunkStart := offset
		dataLength := uint64(binary.BigEndian.Uint32(input[offset : offset+4]))
		chunkEnd64 := uint64(offset) + 12 + dataLength
		if chunkEnd64 > uint64(len(input)) {
			return input
		}
		chunkEnd := int(chunkEnd64)
		chunkType := string(input[offset+4 : offset+8])
		switch chunkType {
		case "eXIf", "iTXt", "tEXt", "zTXt", "tIME", "pHYs":
		default:
			output.Write(input[chunkStart:chunkEnd])
		}
		offset = chunkEnd
		if chunkType == "IEND" {
			foundEnd = true
			break
		}
	}
	if !foundEnd || offset != len(input) {
		return input
	}
	return output.Bytes()
}

func stripWebPMetadata(input []byte) []byte {
	if len(input) < 20 || string(input[:4]) != "RIFF" || string(input[8:12]) != "WEBP" {
		return input
	}
	declaredLength := uint64(binary.LittleEndian.Uint32(input[4:8])) + 8
	if declaredLength > uint64(len(input)) {
		return input
	}
	var chunks bytes.Buffer
	chunks.Grow(len(input) - 12)
	offset := uint64(12)
	changed := false

	for offset+8 <= declaredLength {
		start := int(offset)
		chunkType := string(input[start : start+4])
		dataLength := uint64(binary.LittleEndian.Uint32(input[start+4 : start+8]))
		paddedLength := dataLength + dataLength%2
		chunkEnd := offset + 8 + paddedLength
		if chunkEnd > declaredLength {
			return input
		}
		end := int(chunkEnd)
		switch chunkType {
		case "EXIF", "XMP ":
			changed = true
		case "VP8X":
			if dataLength >= 10 {
				chunk := append([]byte(nil), input[start:end]...)
				if chunk[8]&0x0c != 0 {
					chunk[8] &^= 0x0c
					changed = true
				}
				chunks.Write(chunk)
			} else {
				chunks.Write(input[start:end])
			}
		default:
			chunks.Write(input[start:end])
		}
		offset = chunkEnd
	}
	if !changed || offset != declaredLength {
		return input
	}
	output := make([]byte, 12+chunks.Len())
	copy(output, input[:12])
	copy(output[12:], chunks.Bytes())
	binary.LittleEndian.PutUint32(output[4:8], uint32(len(output)-8))
	return output
}

func stripMP3Metadata(input []byte) []byte {
	start, end := 0, len(input)
	if len(input) >= 10 && string(input[:3]) == "ID3" {
		tagSize := int(input[6]&0x7f)<<21 |
			int(input[7]&0x7f)<<14 |
			int(input[8]&0x7f)<<7 |
			int(input[9]&0x7f)
		footerSize := 0
		if input[3] == 4 && input[5]&0x10 != 0 {
			footerSize = 10
		}
		tagEnd := 10 + tagSize + footerSize
		if tagEnd > len(input) {
			return input
		}
		start = tagEnd
	}
	if end-start >= 128 && string(input[end-128:end-125]) == "TAG" {
		end -= 128
	}
	if start == 0 && end == len(input) {
		return input
	}
	return input[start:end]
}
