package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/sdk/go/wipeme"
)

type consumeIntoFilesInput struct {
	MCPLinkSource
	PassphraseSources    []MCPPassphraseSource `json:"passphrase_sources,omitempty"`
	DestinationDirectory string                `json:"destination_directory"`
	MessageFormat        string                `json:"message_format,omitempty"`
	MessageFilename      string                `json:"message_filename,omitempty"`
	Block                *int                  `json:"block,omitempty"`
	WriteMessage         *bool                 `json:"write_message,omitempty"`
	WriteAttachments     *bool                 `json:"write_attachments,omitempty"`
}

type retryIntoFilesInput struct {
	RecoveryHandle       string `json:"recovery_handle"`
	DestinationDirectory string `json:"destination_directory"`
	MessageFormat        string `json:"message_format,omitempty"`
	MessageFilename      string `json:"message_filename,omitempty"`
	Block                *int   `json:"block,omitempty"`
	WriteMessage         *bool  `json:"write_message,omitempty"`
	WriteAttachments     *bool  `json:"write_attachments,omitempty"`
}

type consumeIntoFilesResult struct {
	Status               string `json:"status"`
	MessageWritten       bool   `json:"message_written"`
	AttachmentCount      int    `json:"attachment_count"`
	DestinationDirectory string `json:"destination_directory"`
	RecoveryDeleted      bool   `json:"recovery_deleted"`
}

type pendingFileConsumptionResult struct {
	Status         string `json:"status"`
	Consumed       bool   `json:"consumed"`
	Retryable      bool   `json:"retryable"`
	RecoveryHandle string `json:"recovery_handle"`
	RetryUntil     string `json:"retry_until"`
	Attempt        int    `json:"attempt"`
}

type mcpFileOutputOptions struct {
	destination      string
	messageFormat    string
	messageFilename  string
	block            int
	writeMessage     bool
	writeAttachments bool
}

type mcpFileConsumptionOutput struct {
	Status               string `json:"status"`
	MessageWritten       bool   `json:"message_written,omitempty"`
	AttachmentCount      int    `json:"attachment_count,omitempty"`
	DestinationDirectory string `json:"destination_directory,omitempty"`
	MessageFilename      string `json:"message_filename,omitempty"`
	RecoveryDeleted      bool   `json:"recovery_deleted,omitempty"`
	Consumed             bool   `json:"consumed,omitempty"`
	Retryable            bool   `json:"retryable,omitempty"`
	RecoveryHandle       string `json:"recovery_handle,omitempty"`
	RetryUntil           string `json:"retry_until,omitempty"`
	Attempt              int    `json:"attempt,omitempty"`
}

func registerMCPFileConsumptionTools(server *mcpsdk.Server, policy mcpPolicy, settings config, store *mcpRecoveryStore) {
	destructive, openWorld := true, true
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "consume_into_files",
		Title:       "Consume into protected files",
		Description: "Consume and decrypt a one-time message into a new private directory, optionally naming the message file, without returning message or attachment plaintext.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input consumeIntoFilesInput) (*mcpsdk.CallToolResult, mcpFileConsumptionOutput, error) {
		options, err := resolveMCPFileOutputOptions(input.DestinationDirectory, input.MessageFormat, input.MessageFilename, input.Block, input.WriteMessage, input.WriteAttachments, policy)
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, err
		}
		privateLink, err := resolveMCPLinkValues(policy, input.PrivateLink, input.LinkFile, input.LinkEnv)
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, err
		}
		application, err := wipeme.ParseApplicationPrivateLink(privateLink)
		privateLink = ""
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, errors.New("invalid_link: private link is invalid")
		}
		candidates, err := mcpCredentialCandidates(application, input.PassphraseSources, policy)
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, err
		}
		defer wipeStrings(candidates)
		if len(candidates) == 0 {
			return nil, mcpFileConsumptionOutput{}, errors.New("credential_unavailable: no passphrase source is available")
		}
		client, err := newAPIClient(settings.APIEndpoint)
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, errors.New("retrieval_failed: service configuration is invalid")
		}
		retrieved, err := client.RetrieveMessage(ctx, application.MessageID)
		if err != nil {
			if api, ok := wipeme.AsAPIError(err); ok && (api.StatusCode == 404 || api.StatusCode == 410) {
				return nil, mcpFileConsumptionOutput{}, errors.New("message_unavailable: message is unavailable or already consumed")
			}
			return nil, mcpFileConsumptionOutput{}, errors.New("retrieval_failed: service request failed")
		}
		record := &mcpRecoveryRecord{
			Type: "consume_files", Envelope: append([]byte(nil), retrieved.Envelope...), MessageID: application.MessageID,
			Secret: application.Secret, Manual: application.CustomPassphrase, Candidates: append([]string(nil), candidates...), Attempt: 1,
		}
		handle, err := store.create(record)
		if err != nil {
			record.wipe()
			return nil, mcpFileConsumptionOutput{}, err
		}
		defer record.wipe()
		decrypted, err := decryptRecoveryRecord(record)
		if err != nil {
			_ = store.discard(handle)
			return nil, mcpFileConsumptionOutput{}, errors.New("credential_rejected: available credentials did not decrypt the message")
		}
		defer wipeResult(&decrypted)
		written, attachments, err := materializeMCPFiles(decrypted, options)
		if err != nil {
			if record.Attempt >= store.maxAttempts {
				if discardErr := store.discard(handle); discardErr != nil {
					return nil, mcpFileConsumptionOutput{}, errors.New("recovery_corrupt: exhausted recovery could not be removed")
				}
				return nil, terminalFileOutput(record), nil
			}
			return nil, pendingFileOutput(handle, record), nil
		}
		if err := store.discard(handle); err != nil {
			return nil, mcpFileConsumptionOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		return nil, successfulFileOutput(options, written, attachments), nil
	})

	closedWorld := false
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "retry_into_files",
		Title:       "Retry protected file output",
		Description: "Retry file materialization with an optional custom message filename from protected local recovery without another server retrieval.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input retryIntoFilesInput) (*mcpsdk.CallToolResult, mcpFileConsumptionOutput, error) {
		options, err := resolveMCPFileOutputOptions(input.DestinationDirectory, input.MessageFormat, input.MessageFilename, input.Block, input.WriteMessage, input.WriteAttachments, policy)
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, err
		}
		lease, record, err := store.acquire(input.RecoveryHandle)
		if err != nil {
			return nil, mcpFileConsumptionOutput{}, err
		}
		defer lease.release()
		defer record.wipe()
		if record.Type != "consume_files" {
			return nil, mcpFileConsumptionOutput{}, errors.New("recovery_unknown: recovery handle has the wrong operation type")
		}
		record.Attempt++
		if err := lease.save(record); err != nil {
			return nil, mcpFileConsumptionOutput{}, err
		}
		decrypted, err := decryptRecoveryRecord(record)
		if err != nil {
			_ = lease.delete()
			return nil, mcpFileConsumptionOutput{}, errors.New("recovery_corrupt: recovery record cannot decrypt the message")
		}
		defer wipeResult(&decrypted)
		written, attachments, err := materializeMCPFiles(decrypted, options)
		if err != nil {
			if record.Attempt >= store.maxAttempts {
				if err := lease.delete(); err != nil {
					return nil, mcpFileConsumptionOutput{}, errors.New("recovery_corrupt: exhausted recovery could not be removed")
				}
				return nil, terminalFileOutput(record), nil
			}
			return nil, pendingFileOutput(input.RecoveryHandle, record), nil
		}
		if err := lease.delete(); err != nil {
			return nil, mcpFileConsumptionOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		return nil, successfulFileOutput(options, written, attachments), nil
	})
}

func resolveMCPFileOutputOptions(destination, format, messageFilename string, block *int, writeMessage, writeAttachments *bool, policy mcpPolicy) (mcpFileOutputOptions, error) {
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "editorjs_json" {
		return mcpFileOutputOptions{}, errors.New("invalid_arguments: message_format must be text or editorjs_json")
	}
	blockIndex := -1
	if block != nil {
		if *block < 0 || format != "text" {
			return mcpFileOutputOptions{}, errors.New("invalid_arguments: block must be non-negative and requires text message_format")
		}
		blockIndex = *block
	}
	message, attachments := true, true
	if writeMessage != nil {
		message = *writeMessage
	}
	if writeAttachments != nil {
		attachments = *writeAttachments
	}
	if !message && !attachments {
		return mcpFileOutputOptions{}, errors.New("invalid_arguments: at least one output type must be enabled")
	}
	if messageFilename != "" && !message {
		return mcpFileOutputOptions{}, errors.New("invalid_arguments: message_filename requires write_message")
	}
	messageFilename, err := resolveMCPMessageFilename(messageFilename, format)
	if err != nil {
		return mcpFileOutputOptions{}, err
	}
	path, err := validateMCPDestination(destination, policy)
	if err != nil {
		return mcpFileOutputOptions{}, err
	}
	return mcpFileOutputOptions{destination: path, messageFormat: format, messageFilename: messageFilename, block: blockIndex, writeMessage: message, writeAttachments: attachments}, nil
}

func resolveMCPMessageFilename(value, format string) (string, error) {
	if value == "" {
		if format == "editorjs_json" {
			return "message.json", nil
		}
		return "message.txt", nil
	}
	if len(value) > 255 || value == "." || value == ".." || strings.ContainsAny(value, "/\\\x00") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("invalid_arguments: message_filename must be a safe basename")
	}
	return value, nil
}

func validateMCPDestination(value string, policy mcpPolicy) (string, error) {
	path, err := normalizeAbsolutePath(value)
	if err != nil || (policy.accessMode != mcpAccessHost && !pathWithinRoots(path, policy.allowedWriteRoots)) {
		return "", errors.New("path_outside_allowed_root: destination directory is not allowed")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return "", errors.New("output_refused: destination directory already exists")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || (policy.accessMode != mcpAccessHost && !pathWithinRoots(parent, policy.allowedWriteRoots)) {
		return "", errors.New("path_outside_allowed_root: destination parent is not allowed")
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func decryptRecoveryRecord(record *mcpRecoveryRecord) (wipeme.DecryptResult, error) {
	application := wipeme.ApplicationLink{MessageID: record.MessageID, Secret: record.Secret, CustomPassphrase: record.Manual}
	return decryptCandidates(record.Envelope, application, record.Candidates)
}

func materializeMCPFiles(result wipeme.DecryptResult, options mcpFileOutputOptions) (bool, int, error) {
	parent := filepath.Dir(options.destination)
	stage, err := os.MkdirTemp(parent, ".wipeme-stage-*")
	if err != nil {
		return false, 0, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, 0o700); err != nil {
		return false, 0, err
	}
	messageWritten := false
	used := map[string]struct{}{}
	if options.writeMessage {
		name := options.messageFilename
		data := []byte(nil)
		if options.messageFormat == "editorjs_json" {
			var formatted bytes.Buffer
			if err := json.Indent(&formatted, []byte(result.Manifest.Message), "", "  "); err != nil {
				return false, 0, err
			}
			data = append(formatted.Bytes(), '\n')
		} else {
			value, ok := selectText(parseDocument(result.Manifest.Message), options.block)
			if !ok {
				if options.block >= 0 {
					return false, 0, errors.New("selected block is not text-compatible")
				}
			} else {
				data = []byte(value)
			}
		}
		if data != nil {
			if err := writePrivate(filepath.Join(stage, name), data); err != nil {
				return false, 0, err
			}
			messageWritten = true
			used[name] = struct{}{}
		}
	}
	attachmentCount := 0
	if options.writeAttachments {
		for index, attachment := range result.Attachments {
			baseName := safeMCPAttachmentBasename(attachment.Metadata.Name, index)
			name := baseName
			for ordinal := index + 1; ; ordinal++ {
				if _, collision := used[name]; !collision {
					break
				}
				name = fmt.Sprintf("%03d-%s", ordinal, baseName)
			}
			if err := writePrivate(filepath.Join(stage, name), attachment.Data); err != nil {
				return false, 0, err
			}
			used[name] = struct{}{}
			attachmentCount++
		}
	}
	if err := os.Rename(stage, options.destination); err != nil {
		return false, 0, err
	}
	complete = true
	return messageWritten, attachmentCount, nil
}

func safeMCPAttachmentBasename(value string, index int) string {
	name := filepath.Base(strings.ReplaceAll(value, "\\", "/"))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return fmt.Sprintf("attachment-%03d.bin", index+1)
	}
	return name
}

func pendingFileOutput(handle string, record *mcpRecoveryRecord) mcpFileConsumptionOutput {
	return mcpFileConsumptionOutput{
		Status: "output_failed", Consumed: true, Retryable: true, RecoveryHandle: handle,
		RetryUntil: record.ExpiresAt.Format(time.RFC3339), Attempt: record.Attempt,
	}
}

func successfulFileOutput(options mcpFileOutputOptions, messageWritten bool, attachmentCount int) mcpFileConsumptionOutput {
	messageFilename := ""
	if messageWritten {
		messageFilename = options.messageFilename
	}
	return mcpFileConsumptionOutput{
		Status: "consumed", MessageWritten: messageWritten, AttachmentCount: attachmentCount,
		DestinationDirectory: options.destination, MessageFilename: messageFilename, RecoveryDeleted: true,
	}
}

func terminalFileOutput(record *mcpRecoveryRecord) mcpFileConsumptionOutput {
	return mcpFileConsumptionOutput{
		Status: "output_failed", Consumed: true, Retryable: false, Attempt: record.Attempt, RecoveryDeleted: true,
	}
}
