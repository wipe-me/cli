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

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/cli/internal/media"
	passwordgen "github.com/wipe-me/cli/internal/password"
	"github.com/wipe-me/sdk/go/wipeme"
	"rsc.io/qr"
)

type MCPPassphraseSource struct {
	PassphraseFile string `json:"passphrase_file,omitempty"`
	PassphraseEnv  string `json:"passphrase_env,omitempty"`
}

type MCPCreationControls struct {
	ExpiresInSeconds int64                `json:"expires_in_seconds,omitempty" jsonschema:"Unopened-message lifetime in seconds."`
	PassphraseSource *MCPPassphraseSource `json:"passphrase_source,omitempty"`
	IncludeQR        bool                 `json:"include_qr,omitempty"`
	ReceiptFile      string               `json:"receipt_file,omitempty"`
	LinkFile         string               `json:"link_file,omitempty"`
}

type generateSecretInput struct {
	MCPCreationControls
	Length          int      `json:"length,omitempty"`
	Chars           string   `json:"chars,omitempty"`
	Alphabet        string   `json:"alphabet,omitempty"`
	NoRequireEach   bool     `json:"no_require_each,omitempty"`
	AttachmentPaths []string `json:"attachment_paths,omitempty"`
}

type createFromFilesInput struct {
	MCPCreationControls
	MessageFile     string   `json:"message_file,omitempty"`
	MessageFormat   string   `json:"message_format,omitempty"`
	AttachmentPaths []string `json:"attachment_paths,omitempty"`
}

type mcpEnvironmentSource struct {
	Source string `json:"source"`
}

type createFromEnvInput struct {
	MCPCreationControls
	Variables []mcpEnvironmentSource `json:"variables"`
}

type mcpCreationResult struct {
	Status          string `json:"status"`
	PrivateLink     string `json:"private_link"`
	MessageID       string `json:"message_id"`
	ExpiresAt       string `json:"expires_at"`
	AttachmentCount int    `json:"attachment_count"`
	QRIncluded      bool   `json:"qr_included"`
	ReceiptWritten  bool   `json:"receipt_written"`
	LinkFileWritten bool   `json:"link_file_written"`
}

type mcpCreateRequest struct {
	controls           MCPCreationControls
	message            string
	files              []media.File
	progress           wipeme.ProgressFunc
	passphraseResolved bool
	passphrase         string
	manual             bool
}

func registerMCPCreationTools(server *mcpsdk.Server, policy mcpPolicy, settings config) {
	mutating, nonDestructive, openWorld := false, false, true
	annotations := &mcpsdk.ToolAnnotations{
		ReadOnlyHint:    mutating,
		DestructiveHint: &nonDestructive,
		IdempotentHint:  false,
		OpenWorldHint:   &openWorld,
	}

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "generate_secret",
		Title:       "Generate a private secret",
		Description: "Generate a password internally, encrypt it into a one-time Wipe.me message, and return only its private link. The plaintext secret is never returned.",
		Annotations: annotations,
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input generateSecretInput) (*mcpsdk.CallToolResult, mcpCreationResult, error) {
		length := input.Length
		if length == 0 {
			length = passwordgen.DefaultLength
		}
		generated, err := passwordgen.Generate(passwordgen.Options{Length: length, Preset: input.Chars, Alphabet: input.Alphabet, NoRequireEach: input.NoRequireEach})
		if err != nil {
			return nil, mcpCreationResult{}, errors.New("invalid_arguments: invalid password generation options")
		}
		defer wipe(generated)
		document, err := encodeTextBlocks([]string{string(generated)})
		if err != nil {
			return nil, mcpCreationResult{}, errors.New("internal_error: prepare encrypted message")
		}
		files, cleanup, err := prepareMCPAttachments(input.AttachmentPaths, policy)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return nil, mcpCreationResult{}, err
		}
		result, png, err := createMCPMessage(ctx, policy, settings, mcpCreateRequest{controls: input.MCPCreationControls, message: document, files: files, progress: mcpProgress(ctx, request)})
		return creationToolResponse(result, png, err)
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "create_from_files",
		Title:       "Create from protected files",
		Description: "Create a one-time encrypted message from an optional message file and one or more attachments permitted by the active access policy. File contents are never returned.",
		Annotations: annotations,
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input createFromFilesInput) (*mcpsdk.CallToolResult, mcpCreationResult, error) {
		if input.MessageFile == "" && len(input.AttachmentPaths) == 0 {
			return nil, mcpCreationResult{}, errors.New("invalid_arguments: at least one input file is required")
		}
		format := input.MessageFormat
		if format == "" {
			format = "text"
		}
		if format != "text" && format != "editorjs_json" {
			return nil, mcpCreationResult{}, errors.New("invalid_arguments: message_format must be text or editorjs_json")
		}
		message := ""
		if input.MessageFile != "" {
			path, err := policy.validateReadFile(input.MessageFile)
			if err != nil {
				return nil, mcpCreationResult{}, fmt.Errorf("%w: message file is unavailable", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, mcpCreationResult{}, errors.New("output_refused: message file is unavailable")
			}
			defer wipe(data)
			if format == "editorjs_json" {
				message = string(data)
				if !validEditorDocument(message) {
					return nil, mcpCreationResult{}, errors.New("invalid_arguments: message file is not a valid Editor.js document")
				}
			} else {
				message, err = encodeTextBlocks([]string{string(data)})
				if err != nil {
					return nil, mcpCreationResult{}, errors.New("internal_error: prepare encrypted message")
				}
			}
		}
		files, cleanup, err := prepareMCPAttachments(input.AttachmentPaths, policy)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return nil, mcpCreationResult{}, err
		}
		result, png, err := createMCPMessage(ctx, policy, settings, mcpCreateRequest{controls: input.MCPCreationControls, message: message, files: files, progress: mcpProgress(ctx, request)})
		return creationToolResponse(result, png, err)
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "create_from_env",
		Title:       "Create from protected environment values",
		Description: "Encrypt one or more server environment values permitted by the active access policy without returning their plaintext.",
		Annotations: annotations,
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input createFromEnvInput) (*mcpsdk.CallToolResult, mcpCreationResult, error) {
		if len(input.Variables) == 0 || len(input.Variables) > policy.maxEnvironmentSources {
			return nil, mcpCreationResult{}, errors.New("invalid_arguments: variables count is outside the configured limit")
		}
		values := make([]string, 0, len(input.Variables))
		defer wipeStrings(values)
		seen := map[string]struct{}{}
		for _, source := range input.Variables {
			if !mcpEnvironmentAllowed(policy, policy.allowedSourceEnv, source.Source) {
				return nil, mcpCreationResult{}, errors.New("invalid_arguments: environment source is not allowed")
			}
			if _, duplicate := seen[source.Source]; duplicate {
				return nil, mcpCreationResult{}, errors.New("invalid_arguments: duplicate environment source")
			}
			seen[source.Source] = struct{}{}
			value, ok := os.LookupEnv(source.Source)
			if !ok || value == "" {
				return nil, mcpCreationResult{}, errors.New("credential_unavailable: environment source is unset or empty")
			}
			values = append(values, value)
		}
		document, err := encodeTextBlocks(values)
		if err != nil {
			return nil, mcpCreationResult{}, errors.New("internal_error: prepare encrypted message")
		}
		result, png, err := createMCPMessage(ctx, policy, settings, mcpCreateRequest{controls: input.MCPCreationControls, message: document, progress: mcpProgress(ctx, request)})
		return creationToolResponse(result, png, err)
	})

	registerMCPProducerTool(server, policy, settings)
}

func createMCPMessage(ctx context.Context, policy mcpPolicy, settings config, request mcpCreateRequest) (result mcpCreationResult, png []byte, err error) {
	expires := settings.Expires
	if expires == 0 {
		expires = 24 * time.Hour
	}
	if request.controls.ExpiresInSeconds != 0 {
		expires = time.Duration(request.controls.ExpiresInSeconds) * time.Second
	}
	if expires <= 0 || expires > wipeme.MaxFreeExpiry {
		return result, nil, errors.New("invalid_arguments: expiry is outside service limits")
	}
	linkPath, receiptPath, err := preflightMCPCreationOutputs(request.controls, policy)
	if err != nil {
		return result, nil, err
	}

	passphrase, manual := request.passphrase, request.manual
	if !request.passphraseResolved {
		passphrase, manual, err = resolveMCPCreationPassphrase(request.controls.PassphraseSource, policy)
		if err != nil {
			return result, nil, err
		}
	}
	defer func() { passphrase = "" }()

	publicID, publicSecret, messageID, secret := "", "", "", ""
	if manual {
		generatedID, generateErr := passwordgen.Generate(passwordgen.Options{Length: wipeme.CustomMessageIDLength, Alphabet: wipeme.Base58BTCAlphabet, NoRequireEach: true})
		if generateErr != nil {
			return result, nil, errors.New("internal_error: generate message capability")
		}
		publicID = string(generatedID)
		wipe(generatedID)
		messageID, secret, err = wipeme.DeriveCustomCryptoParameters(passphrase, publicID)
	} else {
		publicID, publicSecret, err = wipeme.GenerateApplicationCapabilities()
		if err == nil {
			messageID, secret, err = (wipeme.ApplicationLink{MessageID: publicID, Secret: publicSecret}).EnvelopeCryptoParameters()
		}
	}
	if err != nil {
		return result, nil, errors.New("internal_error: derive message capability")
	}
	defer func() { publicSecret, secret = "", "" }()

	message, err := addAttachmentBlocks(request.message, request.files)
	if err != nil {
		return result, nil, errors.New("internal_error: prepare encrypted attachments")
	}
	attachments, closeAttachments, err := openAttachments(request.files)
	if err != nil {
		return result, nil, errors.New("output_refused: attachment is unavailable")
	}
	defer closeAttachments()
	var envelope bytes.Buffer
	encrypted, err := wipeme.EncryptWithOptions(&envelope, messageID, secret, message, attachments, wipeme.CryptoOptions{Progress: request.progress})
	message = ""
	if err != nil {
		return result, nil, errors.New("creation_failed: encryption failed")
	}
	defer wipe(encrypted.DeletionKey[:])

	client, err := newAPIClient(settings.APIEndpoint)
	if err != nil {
		return result, nil, errors.New("creation_failed: service configuration is invalid")
	}
	expiresAt := time.Now().Add(expires)
	created, err := client.CreateMessage(ctx, wipeme.CreateMessageRequest{
		MessageID: publicID, Envelope: envelope.Bytes(), ContentHash: encrypted.ContentHash,
		DeletionKey: encrypted.DeletionKeyHeader, ExpiresAt: expiresAt, Progress: request.progress,
	})
	if err != nil {
		return result, nil, errors.New("creation_failed: service request failed")
	}
	if !created.Created {
		return result, nil, errors.New("creation_failed: service did not create the message")
	}

	link := ""
	if manual {
		link, err = formatManualPrivateLink(settings.SiteURL, publicID)
	} else {
		link, err = wipeme.FormatApplicationPrivateLink(settings.SiteURL, publicID, publicSecret)
	}
	if err != nil {
		return result, nil, errors.New("creation_failed: public site configuration is invalid")
	}
	result = mcpCreationResult{
		Status: "created", PrivateLink: link, MessageID: publicID, ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		AttachmentCount: len(request.files),
	}
	if linkPath != "" {
		linkData := []byte(link + "\n")
		writeErr := writePrivate(linkPath, linkData)
		wipe(linkData)
		if writeErr != nil {
			result.Status = "creation_uncertain"
			return result, nil, nil
		}
		result.LinkFileWritten = true
	}
	if receiptPath != "" {
		receiptSecret := publicSecret
		if manual {
			receiptSecret = passphrase
		}
		receipt := creatorReceipt{CipherVersion: wipeme.ProtocolVersion, URL: link, MessageID: publicID, Secret: receiptSecret, ExpiresAt: expiresAt}
		encoded, encodeErr := json.MarshalIndent(receipt, "", "  ")
		var writeErr error
		if encodeErr == nil {
			encoded = append(encoded, '\n')
			writeErr = writePrivate(receiptPath, encoded)
		}
		wipe(encoded)
		if encodeErr != nil || writeErr != nil {
			result.Status = "creation_uncertain"
			return result, nil, nil
		}
		result.ReceiptWritten = true
	}
	if request.controls.IncludeQR {
		png, err = encodeMCPQRCode(link)
		if err != nil {
			result.Status = "creation_uncertain"
			result.QRIncluded = false
			return result, nil, nil
		}
		result.QRIncluded = true
	}
	return result, png, nil
}

func resolveMCPCreationPassphrase(source *MCPPassphraseSource, policy mcpPolicy) (string, bool, error) {
	if source == nil {
		return "", false, nil
	}
	count := 0
	if source.PassphraseFile != "" {
		count++
	}
	if source.PassphraseEnv != "" {
		count++
	}
	if count != 1 {
		return "", false, errors.New("credential_source_conflict: provide exactly one passphrase source")
	}
	if source.PassphraseFile != "" {
		path, err := policy.validateReadFile(source.PassphraseFile)
		if err != nil {
			return "", false, fmt.Errorf("%w: passphrase file is unavailable", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", false, errors.New("credential_unavailable: passphrase file is unavailable")
		}
		defer wipe(data)
		value := trimLine(string(data))
		if value == "" {
			return "", false, errors.New("credential_unavailable: passphrase source is empty")
		}
		return value, true, nil
	}
	if !mcpEnvironmentAllowed(policy, policy.allowedPassphraseEnv, source.PassphraseEnv) {
		return "", false, errors.New("credential_source_conflict: passphrase environment source is not allowed")
	}
	value, ok := os.LookupEnv(source.PassphraseEnv)
	if !ok || value == "" {
		return "", false, errors.New("credential_unavailable: passphrase environment source is unavailable")
	}
	return value, true, nil
}

func prepareMCPAttachments(paths []string, policy mcpPolicy) ([]media.File, func(), error) {
	files := make([]media.File, 0, len(paths))
	for _, value := range paths {
		path, err := policy.validateReadFile(value)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: attachment is unavailable", err)
		}
		file, err := media.Inspect(path, "", "")
		if err != nil {
			return nil, nil, errors.New("output_refused: attachment is unavailable")
		}
		files = append(files, file)
	}
	cleaned, cleanup, err := sanitizeAttachments(files)
	if err != nil {
		return nil, cleanup, errors.New("output_refused: attachment privacy cleanup failed")
	}
	return cleaned, cleanup, nil
}

func preflightMCPCreationOutputs(controls MCPCreationControls, policy mcpPolicy) (string, string, error) {
	link, err := validateMCPOutputFile(controls.LinkFile, policy)
	if err != nil {
		return "", "", err
	}
	receipt, err := validateMCPOutputFile(controls.ReceiptFile, policy)
	if err != nil {
		return "", "", err
	}
	if link != "" && receipt != "" && link == receipt {
		return "", "", errors.New("invalid_arguments: link_file and receipt_file must differ")
	}
	return link, receipt, nil
}

func validateMCPOutputFile(value string, policy mcpPolicy) (string, error) {
	if value == "" {
		return "", nil
	}
	path, err := normalizeAbsolutePath(value)
	if err != nil || (policy.accessMode != mcpAccessHost && !pathWithinRoots(path, policy.allowedWriteRoots)) {
		return "", errors.New("path_outside_allowed_root: output path is not allowed")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return "", errors.New("output_refused: output already exists")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || (policy.accessMode != mcpAccessHost && !pathWithinRoots(parent, policy.allowedWriteRoots)) {
		return "", errors.New("path_outside_allowed_root: output parent is not allowed")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", errors.New("output_refused: output parent is unavailable")
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func validEditorDocument(value string) bool {
	var document map[string]any
	if json.Unmarshal([]byte(value), &document) != nil {
		return false
	}
	_, ok := document["blocks"].([]any)
	return ok
}

func encodeTextBlocks(values []string) (string, error) {
	blocks := make([]any, 0, len(values))
	for _, value := range values {
		blocks = append(blocks, map[string]any{"type": "paragraph", "data": map[string]any{"text": value}})
	}
	encoded, err := json.Marshal(map[string]any{"blocks": blocks})
	return string(encoded), err
}

func encodeMCPQRCode(link string) ([]byte, error) {
	code, err := qr.Encode(link, qr.M)
	if err != nil {
		return nil, err
	}
	code.Scale = 8
	return code.PNG(), nil
}

func creationToolResponse(result mcpCreationResult, png []byte, err error) (*mcpsdk.CallToolResult, mcpCreationResult, error) {
	if err != nil {
		return nil, mcpCreationResult{}, err
	}
	if len(png) == 0 {
		return nil, result, nil
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, mcpCreationResult{}, errors.New("internal_error: encode creation result")
	}
	return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{
		&mcpsdk.TextContent{Text: string(encoded)},
		&mcpsdk.ImageContent{MIMEType: "image/png", Data: png, Annotations: &mcpsdk.Annotations{Audience: []mcpsdk.Role{mcpsdk.Role("user")}, Priority: 1}},
	}}, result, nil
}

func mcpProgress(ctx context.Context, request *mcpsdk.CallToolRequest) wipeme.ProgressFunc {
	if request == nil || request.Params == nil || request.Session == nil {
		return nil
	}
	token := request.Params.GetProgressToken()
	if token == nil {
		return nil
	}
	return func(event wipeme.Progress) {
		phase := strings.TrimSpace(event.Phase)
		if phase == "" {
			phase = "working"
		}
		percent := event.Percent
		if percent < 0 {
			percent = 0
		} else if percent > 100 {
			percent = 100
		}
		progress := float64(percent)
		switch phase {
		case "encrypting":
			progress *= 0.5
		case "uploading":
			progress = 50 + progress*0.5
		}
		_ = request.Session.NotifyProgress(ctx, &mcpsdk.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      progress,
			Total:         100,
			Message:       phase,
		})
	}
}
