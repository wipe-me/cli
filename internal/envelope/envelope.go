// Package envelope implements the unified wipe.me encrypted envelope v1 format.
package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/wipe-me/cli/internal/base58"
	"github.com/wipe-me/cli/internal/media"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	Version           = 1
	ChunkSize         = 4 * 1024 * 1024
	ManifestLimit     = 16 * 1024 * 1024
	KDFSaltSize       = 32
	DefaultMemoryKiB  = 64 * 1024
	DefaultIterations = 3
	DefaultThreads    = 1
	frameAttachment   = 1
	frameEnd          = 0
)

var magic = [8]byte{'W', 'I', 'P', 'E', 'M', 'E', 0, Version}

// KDFParams are serialized in the public envelope header.
type KDFParams struct {
	MemoryKiB  uint32
	Iterations uint32
	Threads    uint8
}

// DefaultKDFParams returns the fixed v1 Argon2id settings.
func DefaultKDFParams() KDFParams {
	return KDFParams{MemoryKiB: DefaultMemoryKiB, Iterations: DefaultIterations, Threads: DefaultThreads}
}

// Manifest is encrypted and therefore hidden from the storage service.
type Manifest struct {
	Version     int          `json:"version"`
	Message     string       `json:"message,omitempty"`
	ChunkSize   int          `json:"chunk_size"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// Attachment contains private presentation metadata for one attachment.
type Attachment struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Kind        string `json:"kind"`
	Size        int64  `json:"size"`
	Width       int    `json:"width,omitempty"`
	Height      int    `json:"height,omitempty"`
	Chunks      uint32 `json:"chunks"`
	NoncePrefix string `json:"nonce_prefix"`
}

// WriteOptions controls envelope creation. Zero values select secure defaults.
type WriteOptions struct {
	Random io.Reader
	KDF    KDFParams
}

// WriteResult contains encrypted metadata plus the server deletion capability.
// DeletionKey must be wiped by the caller after the create request completes.
type WriteResult struct {
	Manifest    Manifest
	DeletionKey [32]byte
}

// DecryptedAttachment is returned by Read for interoperability tests and tools.
type DecryptedAttachment struct {
	Metadata Attachment
	Data     []byte
}

// Decrypted is an in-memory decrypted envelope.
type Decrypted struct {
	Manifest    Manifest
	Attachments []DecryptedAttachment
}

// Write encrypts a message and local attachments into one streaming envelope.
func Write(output io.Writer, messageID, message, secret string, files []media.File, options WriteOptions) (WriteResult, error) {
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.KDF == (KDFParams{}) {
		options.KDF = DefaultKDFParams()
	}
	if err := validateKDF(options.KDF); err != nil {
		return WriteResult{}, err
	}
	if !base58.Valid(messageID, 12) {
		return WriteResult{}, fmt.Errorf("message ID must contain 12 canonical Base58 characters")
	}
	if !base58.Valid(secret, 16) {
		return WriteResult{}, fmt.Errorf("secret must contain 16 canonical Base58 characters")
	}

	salt := kdfSalt(messageID)
	manifestNonce := make([]byte, 12)
	if _, err := io.ReadFull(options.Random, manifestNonce); err != nil {
		return WriteResult{}, fmt.Errorf("generate manifest nonce: %w", err)
	}

	manifest := Manifest{Version: Version, Message: message, ChunkSize: ChunkSize}
	rawIDs := make([][]byte, len(files))
	for i, file := range files {
		if file.Size < 0 {
			return WriteResult{}, fmt.Errorf("attachment %q has invalid size", file.Name)
		}
		id := make([]byte, 16)
		prefix := make([]byte, 8)
		if _, err := io.ReadFull(options.Random, id); err != nil {
			return WriteResult{}, fmt.Errorf("generate attachment ID: %w", err)
		}
		if _, err := io.ReadFull(options.Random, prefix); err != nil {
			return WriteResult{}, fmt.Errorf("generate attachment nonce: %w", err)
		}
		rawIDs[i] = id
		manifest.Attachments = append(manifest.Attachments, Attachment{
			ID:          hex.EncodeToString(id),
			Name:        file.Name,
			Type:        file.Type,
			Kind:        file.Kind,
			Size:        file.Size,
			Width:       file.Width,
			Height:      file.Height,
			Chunks:      chunkCount(file.Size),
			NoncePrefix: hex.EncodeToString(prefix),
		})
	}

	rootKey := argon2.IDKey([]byte(secret), salt, options.KDF.Iterations, options.KDF.MemoryKiB, options.KDF.Threads, 32)
	defer wipe(rootKey)
	encryptionRoot, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/encryption"))
	if err != nil {
		return WriteResult{}, err
	}
	defer wipe(encryptionRoot)
	deletionKey, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/deletion"))
	if err != nil {
		return WriteResult{}, err
	}
	defer wipe(deletionKey)
	manifestKey, err := deriveKey(encryptionRoot, []byte("wipe.me/envelope/v1/manifest"))
	if err != nil {
		return WriteResult{}, err
	}
	defer wipe(manifestKey)

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return WriteResult{}, fmt.Errorf("encode manifest: %w", err)
	}
	publicHeader := encodePublicHeader(options.KDF, salt, manifestNonce)
	manifestAEAD, err := newGCM(manifestKey)
	if err != nil {
		return WriteResult{}, err
	}
	manifestCiphertext := manifestAEAD.Seal(nil, manifestNonce, manifestJSON, publicHeader)
	if len(manifestCiphertext) > ManifestLimit {
		return WriteResult{}, fmt.Errorf("encrypted manifest exceeds %d bytes", ManifestLimit)
	}

	if err := writeFull(output, publicHeader); err != nil {
		return WriteResult{}, err
	}
	if err := writeUint32(output, uint32(len(manifestCiphertext))); err != nil {
		return WriteResult{}, err
	}
	if err := writeFull(output, manifestCiphertext); err != nil {
		return WriteResult{}, err
	}

	for index, file := range files {
		if err := writeAttachment(output, encryptionRoot, uint32(index), rawIDs[index], file, manifest.Attachments[index]); err != nil {
			return WriteResult{}, err
		}
	}
	if err := writeFull(output, []byte{frameEnd}); err != nil {
		return WriteResult{}, err
	}
	result := WriteResult{Manifest: manifest}
	copy(result.DeletionKey[:], deletionKey)
	return result, nil
}

func writeAttachment(output io.Writer, encryptionRoot []byte, index uint32, id []byte, file media.File, metadata Attachment) error {
	key, err := deriveKey(encryptionRoot, append([]byte("wipe.me/envelope/v1/attachment/"), id...))
	if err != nil {
		return err
	}
	defer wipe(key)
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	prefix, err := hex.DecodeString(metadata.NoncePrefix)
	if err != nil {
		return fmt.Errorf("decode attachment nonce prefix: %w", err)
	}
	handle, err := os.Open(file.Path)
	if err != nil {
		return fmt.Errorf("open attachment %q: %w", file.Path, err)
	}
	defer handle.Close()

	buffer := make([]byte, ChunkSize)
	remaining := file.Size
	for chunk := uint32(0); chunk < metadata.Chunks; chunk++ {
		plainLength := int64(ChunkSize)
		if remaining < plainLength {
			plainLength = remaining
		}
		plaintext := buffer[:plainLength]
		if _, err := io.ReadFull(handle, plaintext); err != nil {
			return fmt.Errorf("read attachment %q chunk %d: %w", file.Name, chunk, err)
		}
		header := encodeFrameHeader(index, chunk, uint32(plainLength))
		nonce := chunkNonce(prefix, chunk)
		aad := chunkAAD(header, metadata.Chunks, id)
		ciphertext := aead.Seal(nil, nonce, plaintext, aad)
		if err := writeFull(output, header); err != nil {
			return err
		}
		if err := writeFull(output, ciphertext); err != nil {
			return err
		}
		remaining -= plainLength
	}
	var extra [1]byte
	if n, readErr := handle.Read(extra[:]); n != 0 || (readErr != nil && readErr != io.EOF) {
		return fmt.Errorf("attachment %q changed while it was encrypted", file.Name)
	}
	return nil
}

// Read decrypts an envelope. It is intentionally strict and rejects reordered,
// missing, oversized, or unauthenticated frames.
func Read(input io.Reader, messageID, secret string) (Decrypted, error) {
	if !base58.Valid(messageID, 12) || !base58.Valid(secret, 16) {
		return Decrypted{}, fmt.Errorf("invalid message ID or secret")
	}
	publicHeader := make([]byte, 8+4+4+1+KDFSaltSize+12)
	if _, err := io.ReadFull(input, publicHeader); err != nil {
		return Decrypted{}, fmt.Errorf("read envelope header: %w", err)
	}
	if !bytes.Equal(publicHeader[:8], magic[:]) {
		return Decrypted{}, fmt.Errorf("unsupported envelope magic or version")
	}
	params := KDFParams{
		MemoryKiB:  binary.BigEndian.Uint32(publicHeader[8:12]),
		Iterations: binary.BigEndian.Uint32(publicHeader[12:16]),
		Threads:    publicHeader[16],
	}
	if err := validateKDF(params); err != nil {
		return Decrypted{}, err
	}
	salt := publicHeader[17 : 17+KDFSaltSize]
	expectedSalt := kdfSalt(messageID)
	if !bytes.Equal(salt, expectedSalt) {
		return Decrypted{}, fmt.Errorf("envelope does not match message ID")
	}
	manifestNonce := publicHeader[17+KDFSaltSize:]
	manifestLength, err := readUint32(input)
	if err != nil {
		return Decrypted{}, err
	}
	if manifestLength < 16 || manifestLength > ManifestLimit {
		return Decrypted{}, fmt.Errorf("invalid encrypted manifest length %d", manifestLength)
	}
	manifestCiphertext := make([]byte, manifestLength)
	if _, err := io.ReadFull(input, manifestCiphertext); err != nil {
		return Decrypted{}, fmt.Errorf("read encrypted manifest: %w", err)
	}

	rootKey := argon2.IDKey([]byte(secret), salt, params.Iterations, params.MemoryKiB, params.Threads, 32)
	defer wipe(rootKey)
	encryptionRoot, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/encryption"))
	if err != nil {
		return Decrypted{}, err
	}
	defer wipe(encryptionRoot)
	manifestKey, err := deriveKey(encryptionRoot, []byte("wipe.me/envelope/v1/manifest"))
	if err != nil {
		return Decrypted{}, err
	}
	defer wipe(manifestKey)
	aead, err := newGCM(manifestKey)
	if err != nil {
		return Decrypted{}, err
	}
	manifestJSON, err := aead.Open(nil, manifestNonce, manifestCiphertext, publicHeader)
	if err != nil {
		return Decrypted{}, fmt.Errorf("decrypt manifest: invalid secret or damaged envelope")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return Decrypted{}, fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.Version != Version || manifest.ChunkSize != ChunkSize {
		return Decrypted{}, fmt.Errorf("unsupported encrypted manifest version")
	}

	result := Decrypted{Manifest: manifest, Attachments: make([]DecryptedAttachment, len(manifest.Attachments))}
	for i, metadata := range manifest.Attachments {
		if metadata.Size < 0 || metadata.Chunks != chunkCount(metadata.Size) {
			return Decrypted{}, fmt.Errorf("invalid attachment %d layout", i)
		}
		if metadata.Size > int64(^uint(0)>>1) {
			return Decrypted{}, fmt.Errorf("attachment %d is too large for this system", i)
		}
		result.Attachments[i] = DecryptedAttachment{Metadata: metadata, Data: make([]byte, 0, int(metadata.Size))}
	}

	for attachmentIndex, metadata := range manifest.Attachments {
		id, err := hex.DecodeString(metadata.ID)
		if err != nil || len(id) != 16 {
			return Decrypted{}, fmt.Errorf("invalid attachment %d ID", attachmentIndex)
		}
		prefix, err := hex.DecodeString(metadata.NoncePrefix)
		if err != nil || len(prefix) != 8 {
			return Decrypted{}, fmt.Errorf("invalid attachment %d nonce prefix", attachmentIndex)
		}
		key, err := deriveKey(encryptionRoot, append([]byte("wipe.me/envelope/v1/attachment/"), id...))
		if err != nil {
			return Decrypted{}, err
		}
		attachmentAEAD, err := newGCM(key)
		if err != nil {
			wipe(key)
			return Decrypted{}, err
		}
		for chunk := uint32(0); chunk < metadata.Chunks; chunk++ {
			header := make([]byte, 13)
			if _, err := io.ReadFull(input, header); err != nil {
				wipe(key)
				return Decrypted{}, fmt.Errorf("read attachment frame: %w", err)
			}
			if header[0] != frameAttachment || binary.BigEndian.Uint32(header[1:5]) != uint32(attachmentIndex) || binary.BigEndian.Uint32(header[5:9]) != chunk {
				wipe(key)
				return Decrypted{}, fmt.Errorf("unexpected attachment frame order")
			}
			plainLength := binary.BigEndian.Uint32(header[9:13])
			if plainLength > ChunkSize || (plainLength == 0 && metadata.Size != 0) {
				wipe(key)
				return Decrypted{}, fmt.Errorf("invalid attachment chunk length")
			}
			ciphertext := make([]byte, int(plainLength)+attachmentAEAD.Overhead())
			if _, err := io.ReadFull(input, ciphertext); err != nil {
				wipe(key)
				return Decrypted{}, fmt.Errorf("read encrypted attachment chunk: %w", err)
			}
			plaintext, err := attachmentAEAD.Open(nil, chunkNonce(prefix, chunk), ciphertext, chunkAAD(header, metadata.Chunks, id))
			if err != nil {
				wipe(key)
				return Decrypted{}, fmt.Errorf("decrypt attachment %d chunk %d: damaged envelope", attachmentIndex, chunk)
			}
			result.Attachments[attachmentIndex].Data = append(result.Attachments[attachmentIndex].Data, plaintext...)
		}
		wipe(key)
		if int64(len(result.Attachments[attachmentIndex].Data)) != metadata.Size {
			return Decrypted{}, fmt.Errorf("attachment %d size mismatch", attachmentIndex)
		}
	}
	var end [1]byte
	if _, err := io.ReadFull(input, end[:]); err != nil || end[0] != frameEnd {
		return Decrypted{}, fmt.Errorf("missing envelope end frame")
	}
	var extra [1]byte
	if n, err := input.Read(extra[:]); n != 0 || (err != nil && err != io.EOF) {
		return Decrypted{}, fmt.Errorf("unexpected data after envelope")
	}
	return result, nil
}

func encodePublicHeader(params KDFParams, salt, nonce []byte) []byte {
	header := make([]byte, 0, 8+4+4+1+KDFSaltSize+12)
	header = append(header, magic[:]...)
	header = binary.BigEndian.AppendUint32(header, params.MemoryKiB)
	header = binary.BigEndian.AppendUint32(header, params.Iterations)
	header = append(header, params.Threads)
	header = append(header, salt...)
	header = append(header, nonce...)
	return header
}

// DeriveDeletionKey reconstructs the v1 deletion capability from a complete
// link's canonical message ID and secret.
func DeriveDeletionKey(messageID, secret string) ([32]byte, error) {
	var result [32]byte
	if !base58.Valid(messageID, 12) {
		return result, fmt.Errorf("message ID must contain 12 canonical Base58 characters")
	}
	if !base58.Valid(secret, 16) {
		return result, fmt.Errorf("secret must contain 16 canonical Base58 characters")
	}
	params := DefaultKDFParams()
	rootKey := argon2.IDKey([]byte(secret), kdfSalt(messageID), params.Iterations, params.MemoryKiB, params.Threads, 32)
	defer wipe(rootKey)
	key, err := deriveKey(rootKey, []byte("wipe.me/envelope/v1/deletion"))
	if err != nil {
		return result, err
	}
	defer wipe(key)
	copy(result[:], key)
	return result, nil
}

func kdfSalt(messageID string) []byte {
	digest := sha256.Sum256([]byte("wipe.me/envelope/v1/kdf-salt/" + messageID))
	return digest[:]
}

func encodeFrameHeader(attachment, chunk, plaintextLength uint32) []byte {
	header := []byte{frameAttachment}
	header = binary.BigEndian.AppendUint32(header, attachment)
	header = binary.BigEndian.AppendUint32(header, chunk)
	header = binary.BigEndian.AppendUint32(header, plaintextLength)
	return header
}

func chunkAAD(header []byte, chunks uint32, id []byte) []byte {
	aad := make([]byte, 0, len(magic)+len(header)+4+len(id))
	aad = append(aad, magic[:]...)
	aad = append(aad, header...)
	aad = binary.BigEndian.AppendUint32(aad, chunks)
	aad = append(aad, id...)
	return aad
}

func chunkNonce(prefix []byte, chunk uint32) []byte {
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, prefix...)
	nonce = binary.BigEndian.AppendUint32(nonce, chunk)
	return nonce
}

func chunkCount(size int64) uint32 {
	if size <= 0 {
		return 0
	}
	return uint32((size + ChunkSize - 1) / ChunkSize)
}

func deriveKey(rootKey, info []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, rootKey, nil, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive envelope key: %w", err)
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-GCM: %w", err)
	}
	return aead, nil
}

func validateKDF(params KDFParams) error {
	if params.MemoryKiB == 0 || params.MemoryKiB > 256*1024 {
		return fmt.Errorf("invalid Argon2id memory cost %d KiB", params.MemoryKiB)
	}
	if params.Iterations == 0 || params.Iterations > 10 {
		return fmt.Errorf("invalid Argon2id iteration count %d", params.Iterations)
	}
	if params.Threads == 0 || params.Threads > 16 {
		return fmt.Errorf("invalid Argon2id parallelism %d", params.Threads)
	}
	return nil
}

func writeUint32(writer io.Writer, value uint32) error {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return writeFull(writer, encoded[:])
}

func readUint32(reader io.Reader) (uint32, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return 0, fmt.Errorf("read uint32: %w", err)
	}
	return binary.BigEndian.Uint32(encoded[:]), nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return fmt.Errorf("write envelope: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
