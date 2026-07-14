// Package api uploads encrypted envelopes to a wipe.me-compatible service.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/wipe-me/cli/internal/base58"
)

const ContentType = "application/octet-stream"

// Client is a minimal wipe.me API client.
type Client struct {
	Endpoint   string
	HTTPClient *http.Client
	UserAgent  string
}

// CreateResponse describes a stored one-time envelope.
type CreateResponse struct {
	MessageID string `json:"id"`
	Created   bool   `json:"created"`
}

// Create uploads an already encrypted and seekable envelope.
func (client Client) Create(ctx context.Context, messageID string, envelope io.ReadSeeker, size int64, expiresAt time.Time, deletionKey []byte) (CreateResponse, error) {
	if client.Endpoint == "" {
		return CreateResponse{}, fmt.Errorf("API endpoint is required")
	}
	if !base58.Valid(messageID, 12) {
		return CreateResponse{}, fmt.Errorf("message ID must contain 12 canonical Base58 characters")
	}
	if len(deletionKey) != 32 {
		return CreateResponse{}, fmt.Errorf("deletion key must contain 32 bytes")
	}
	if !expiresAt.After(time.Now()) {
		return CreateResponse{}, fmt.Errorf("expiration must be in the future")
	}
	contentHash, err := hashEnvelope(envelope)
	if err != nil {
		return CreateResponse{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, client.messageEndpoint(messageID), envelope)
	if err != nil {
		return CreateResponse{}, fmt.Errorf("create upload request: %w", err)
	}
	request.ContentLength = size
	request.Header.Set("Content-Type", ContentType)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Wipe-Content-Hash", contentHash)
	request.Header.Set("X-Wipe-Deletion-Key", base64.RawURLEncoding.EncodeToString(deletionKey))
	request.Header.Set("X-Wipe-Cipher-Version", "1")
	request.Header.Set("X-Wipe-Client", "cli")
	request.Header.Set("X-Wipe-Expires-At", fmt.Sprintf("%d", expiresAt.UnixMilli()))
	request.Header.Set("X-Wipe-On-Read", "1")
	if client.UserAgent != "" {
		request.Header.Set("User-Agent", client.UserAgent)
	}

	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return CreateResponse{}, fmt.Errorf("upload encrypted message: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return CreateResponse{}, fmt.Errorf("read API response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		var apiError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &apiError) == nil && apiError.Error != "" {
			message = apiError.Error
		}
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return CreateResponse{}, fmt.Errorf("wipe.me API returned %s: %s", response.Status, message)
	}

	var created CreateResponse
	if err := json.Unmarshal(body, &created); err != nil {
		return CreateResponse{}, fmt.Errorf("decode API response: %w", err)
	}
	if created.MessageID != messageID {
		return CreateResponse{}, fmt.Errorf("API returned an unexpected message ID")
	}
	return created, nil
}

// Delete permanently removes a message using its derived deletion capability.
func (client Client) Delete(ctx context.Context, messageID string, deletionKey []byte) error {
	if client.Endpoint == "" {
		return fmt.Errorf("API endpoint is required")
	}
	if !base58.Valid(messageID, 12) {
		return fmt.Errorf("message ID must contain 12 canonical Base58 characters")
	}
	if len(deletionKey) != 32 {
		return fmt.Errorf("deletion key must contain 32 bytes")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, client.messageEndpoint(messageID), nil)
	if err != nil {
		return fmt.Errorf("create deletion request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Wipe-Deletion-Key", base64.RawURLEncoding.EncodeToString(deletionKey))
	if client.UserAgent != "" {
		request.Header.Set("User-Agent", client.UserAgent)
	}
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("delete encrypted message: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read deletion response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return apiResponseError(response, body)
	}
	var deleted struct {
		Deleted bool `json:"deleted"`
	}
	if err := json.Unmarshal(body, &deleted); err != nil || !deleted.Deleted {
		return fmt.Errorf("API returned an invalid deletion response")
	}
	return nil
}

func (client Client) messageEndpoint(messageID string) string {
	return strings.TrimRight(client.Endpoint, "/") + "/" + messageID
}

func hashEnvelope(envelope io.ReadSeeker) (string, error) {
	if _, err := envelope.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind encrypted envelope: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, envelope); err != nil {
		return "", fmt.Errorf("hash encrypted envelope: %w", err)
	}
	if _, err := envelope.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind encrypted envelope: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func apiResponseError(response *http.Response, body []byte) error {
	message := strings.TrimSpace(string(body))
	var apiError struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &apiError) == nil && apiError.Error != "" {
		message = apiError.Error
	}
	if message == "" {
		message = http.StatusText(response.StatusCode)
	}
	return fmt.Errorf("wipe.me API returned %s: %s", response.Status, message)
}
