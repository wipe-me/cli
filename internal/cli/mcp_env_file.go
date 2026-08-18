package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	passwordgen "github.com/wipe-me/cli/internal/password"
	"github.com/wipe-me/sdk/go/wipeme"
)

const (
	mcpEnvFormatDotenv  = "dotenv"
	mcpEnvFormatDocker  = "docker"
	mcpEnvFormatShell   = "shell"
	mcpEnvFormatSystemd = "systemd"
	mcpEnvFormatMarker  = "# wipeme-format: "
)

var errMCPEnvCredentialRejected = errors.New("environment file recovery credentials were rejected")

type consumeIntoEnvFileInput struct {
	MCPLinkSource
	PassphraseSources []MCPPassphraseSource    `json:"passphrase_sources,omitempty"`
	DestinationFile   string                   `json:"destination_file"`
	Environment       []mcpEnvironmentSelector `json:"environment"`
	Format            string                   `json:"format,omitempty" jsonschema:"dotenv, docker, shell, or systemd; omit for dotenv on a new file or autodetection when overwriting"`
	Overwrite         bool                     `json:"overwrite,omitempty"`
}

type retryIntoEnvFileInput struct {
	RecoveryHandle  string                   `json:"recovery_handle"`
	DestinationFile string                   `json:"destination_file,omitempty"`
	Environment     []mcpEnvironmentSelector `json:"environment,omitempty"`
	Format          string                   `json:"format,omitempty" jsonschema:"dotenv, docker, shell, or systemd; omit to reuse or autodetect the destination format"`
	Overwrite       *bool                    `json:"overwrite,omitempty"`
	IncludeQR       bool                     `json:"include_qr,omitempty"`
}

type generateSecretIntoEnvFileInput struct {
	MCPCreationControls
	Length          int                      `json:"length,omitempty"`
	Chars           string                   `json:"chars,omitempty"`
	Alphabet        string                   `json:"alphabet,omitempty"`
	NoRequireEach   bool                     `json:"no_require_each,omitempty"`
	DestinationFile string                   `json:"destination_file"`
	Environment     []mcpEnvironmentSelector `json:"environment"`
	Format          string                   `json:"format,omitempty" jsonschema:"dotenv, docker, shell, or systemd; omit for dotenv on a new file or autodetection when overwriting"`
	Overwrite       bool                     `json:"overwrite,omitempty"`
}

type mcpEnvFileOptions struct {
	destination string
	mappings    []mcpEnvironmentMapping
	format      string
	overwrite   bool
}

type mcpEnvFileOutput struct {
	Status               string `json:"status"`
	Consumed             bool   `json:"consumed,omitempty"`
	RemoteMessageCreated bool   `json:"remote_message_created,omitempty"`
	DestinationFile      string `json:"destination_file,omitempty"`
	Format               string `json:"format,omitempty"`
	VariablesWritten     int    `json:"variables_written,omitempty"`
	Attempt              int    `json:"attempt"`
	Retryable            bool   `json:"retryable"`
	RecoveryHandle       string `json:"recovery_handle,omitempty"`
	RetryUntil           string `json:"retry_until,omitempty"`
	RecoveryDeleted      bool   `json:"recovery_deleted"`
	PrivateLink          string `json:"private_link,omitempty"`
	MessageID            string `json:"message_id,omitempty"`
	ExpiresAt            string `json:"expires_at,omitempty"`
	QRIncluded           bool   `json:"qr_included,omitempty"`
	ReceiptWritten       bool   `json:"receipt_written,omitempty"`
	LinkFileWritten      bool   `json:"link_file_written,omitempty"`
}

func registerMCPEnvFileTools(server *mcpsdk.Server, policy mcpPolicy, settings config, store *mcpRecoveryStore) {
	destructive, openWorld, closedWorld := true, true, false

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "consume_into_env_file",
		Title:       "Consume into an environment file",
		Description: "Preferred for repeatable commands and containers: consume once and write selected text blocks to a reusable private dotenv, Docker, shell, or systemd environment file without returning plaintext.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input consumeIntoEnvFileInput) (*mcpsdk.CallToolResult, mcpEnvFileOutput, error) {
		options, err := resolveMCPEnvFileOptions(input.DestinationFile, input.Environment, input.Format, input.Overwrite, policy, false)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		privateLink, err := resolveMCPLinkValues(policy, input.PrivateLink, input.LinkFile, input.LinkEnv)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		application, err := wipeme.ParseApplicationPrivateLink(privateLink)
		privateLink = ""
		if err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("invalid_link: private link is invalid")
		}
		candidates, err := mcpCredentialCandidates(application, input.PassphraseSources, policy)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		defer wipeStrings(candidates)
		if len(candidates) == 0 {
			return nil, mcpEnvFileOutput{}, errors.New("credential_unavailable: no passphrase source is available")
		}
		client, err := newAPIClient(settings.APIEndpoint)
		if err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("retrieval_failed: service configuration is invalid")
		}
		retrieved, err := client.RetrieveMessage(ctx, application.MessageID)
		if err != nil {
			return nil, mcpEnvFileOutput{}, sanitizedMCPRetrievalError(err)
		}
		record := &mcpRecoveryRecord{
			Type: "consume_env_file", Envelope: append([]byte(nil), retrieved.Envelope...), MessageID: application.MessageID,
			Secret: application.Secret, Manual: application.CustomPassphrase, Candidates: append([]string(nil), candidates...),
			Environment: options.mappings, DestinationFile: options.destination, EnvFileFormat: options.format,
			Overwrite: options.overwrite, Attempt: 1,
		}
		handle, err := store.create(record)
		if err != nil {
			record.wipe()
			return nil, mcpEnvFileOutput{}, err
		}
		defer record.wipe()
		if err := materializeMCPEnvFileRecovery(record, options); err != nil {
			if errors.Is(err, errMCPEnvCredentialRejected) {
				_ = store.discard(handle)
				return nil, mcpEnvFileOutput{}, errors.New("credential_rejected: available credentials did not decrypt the message")
			}
			return nil, envFileFailure(ctx, record, handle, store, settings, nil), nil
		}
		if err := store.discard(handle); err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		return nil, successfulConsumedEnvFileOutput(record, options), nil
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "generate_secret_into_env_file",
		Title:       "Generate a secret into an environment file",
		Description: "Preferred for repeatable commands and containers: generate one password, upload it, and write the same value to a reusable private environment file. Release the link only after the file is complete.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input generateSecretIntoEnvFileInput) (*mcpsdk.CallToolResult, mcpEnvFileOutput, error) {
		options, err := resolveMCPEnvFileOptions(input.DestinationFile, input.Environment, input.Format, input.Overwrite, policy, true)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		linkPath, receiptPath, err := preflightMCPCreationOutputs(input.MCPCreationControls, policy)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		if options.destination == linkPath || options.destination == receiptPath {
			return nil, mcpEnvFileOutput{}, errors.New("invalid_arguments: destination_file must differ from link_file and receipt_file")
		}
		passphrase, manual, err := resolveMCPCreationPassphrase(input.PassphraseSource, policy)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		defer func() { passphrase = "" }()
		length := input.Length
		if length == 0 {
			length = passwordgen.DefaultLength
		}
		generated, err := passwordgen.Generate(passwordgen.Options{Length: length, Preset: input.Chars, Alphabet: input.Alphabet, NoRequireEach: input.NoRequireEach})
		if err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("invalid_arguments: invalid password generation options")
		}
		defer wipe(generated)
		document, _ := encodeTextBlocks([]string{string(generated)})
		controls := input.MCPCreationControls
		controls.IncludeQR, controls.LinkFile, controls.ReceiptFile = false, "", ""
		created, _, err := createMCPMessage(ctx, policy, settings, mcpCreateRequest{
			controls: controls, message: document, progress: mcpProgress(ctx, request),
			passphraseResolved: true, passphrase: passphrase, manual: manual,
		})
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		application, err := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
		if err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("internal_error: retain generated capability")
		}
		candidate, creatorSecret := application.Secret, application.Secret
		if manual {
			candidate, creatorSecret = passphrase, passphrase
		}
		record := &mcpRecoveryRecord{
			Type: "generate_env_file", MessageID: application.MessageID, Secret: application.Secret, Manual: manual,
			Candidates: []string{candidate}, Environment: options.mappings, DestinationFile: options.destination,
			EnvFileFormat: options.format, Overwrite: options.overwrite, GeneratedSecret: string(generated),
			PrivateLink: created.PrivateLink, MessageExpiresAt: created.ExpiresAt, AttachmentCount: created.AttachmentCount,
			CreatorSecret: creatorSecret, ReceiptFile: receiptPath, LinkFile: linkPath, Attempt: 1,
		}
		handle, err := store.create(record)
		if err != nil {
			_, _, _ = deleteGeneratedRecoveryRemote(ctx, record, settings)
			record.wipe()
			return nil, mcpEnvFileOutput{}, err
		}
		defer record.wipe()
		if err := materializeMCPGeneratedEnvFile(record, options); err != nil {
			return nil, envFileFailure(ctx, record, handle, store, settings, nil), nil
		}
		if err := store.discard(handle); err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		output, png := finalizeGeneratedEnvFile(record, options, input.IncludeQR)
		return envFileToolResponse(output, png, nil)
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "retry_into_env_file",
		Title:       "Retry environment file output",
		Description: "Retry reusable environment-file output from protected local recovery without retrieving, consuming, uploading, or generating again.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input retryIntoEnvFileInput) (*mcpsdk.CallToolResult, mcpEnvFileOutput, error) {
		lease, record, err := store.acquire(input.RecoveryHandle)
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		defer lease.release()
		defer record.wipe()
		if record.Type != "consume_env_file" && record.Type != "generate_env_file" {
			return nil, mcpEnvFileOutput{}, errors.New("recovery_unknown: recovery handle has the wrong operation type")
		}
		destination := record.DestinationFile
		if input.DestinationFile != "" {
			destination = input.DestinationFile
		}
		selectors := mappingsToSelectors(record.Environment)
		if input.Environment != nil {
			selectors = input.Environment
		}
		format := record.EnvFileFormat
		if input.Format != "" {
			format = input.Format
		}
		overwrite := record.Overwrite
		if input.Overwrite != nil {
			overwrite = *input.Overwrite
		}
		options, err := resolveMCPEnvFileOptions(destination, selectors, format, overwrite, policy, record.Type == "generate_env_file")
		if err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		if record.Type == "generate_env_file" && (options.destination == record.LinkFile || options.destination == record.ReceiptFile) {
			return nil, mcpEnvFileOutput{}, errors.New("invalid_arguments: destination_file must differ from link_file and receipt_file")
		}
		record.DestinationFile, record.Environment = options.destination, options.mappings
		record.EnvFileFormat, record.Overwrite = options.format, options.overwrite
		record.Attempt++
		if err := lease.save(record); err != nil {
			return nil, mcpEnvFileOutput{}, err
		}
		if record.Type == "consume_env_file" {
			err = materializeMCPEnvFileRecovery(record, options)
		} else {
			err = materializeMCPGeneratedEnvFile(record, options)
		}
		if err != nil {
			if errors.Is(err, errMCPEnvCredentialRejected) {
				_ = lease.delete()
				return nil, mcpEnvFileOutput{}, errors.New("recovery_corrupt: recovery record cannot decrypt the message")
			}
			return nil, envFileFailure(ctx, record, input.RecoveryHandle, store, settings, lease), nil
		}
		if err := lease.delete(); err != nil {
			return nil, mcpEnvFileOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		if record.Type == "generate_env_file" {
			output, png := finalizeGeneratedEnvFile(record, options, input.IncludeQR)
			return envFileToolResponse(output, png, nil)
		}
		return nil, successfulConsumedEnvFileOutput(record, options), nil
	})
}

func resolveMCPEnvFileOptions(destination string, selectors []mcpEnvironmentSelector, format string, overwrite bool, policy mcpPolicy, generated bool) (mcpEnvFileOptions, error) {
	mappings, err := validateMCPEnvFileMappings(selectors)
	if err != nil {
		return mcpEnvFileOptions{}, err
	}
	if generated {
		for _, mapping := range mappings {
			if mapping.Block > 0 {
				return mcpEnvFileOptions{}, errors.New("invalid_arguments: generated secrets only contain block 0")
			}
		}
	}
	path, err := validateMCPEnvFileDestination(destination, overwrite, policy)
	if err != nil {
		return mcpEnvFileOptions{}, err
	}
	if format == "" {
		format, err = detectMCPEnvFileFormat(path)
		if err != nil {
			return mcpEnvFileOptions{}, err
		}
	}
	if format != mcpEnvFormatDotenv && format != mcpEnvFormatDocker && format != mcpEnvFormatShell && format != mcpEnvFormatSystemd {
		return mcpEnvFileOptions{}, errors.New("invalid_arguments: format must be dotenv, docker, shell, or systemd")
	}
	return mcpEnvFileOptions{destination: path, mappings: mappings, format: format, overwrite: overwrite}, nil
}

func detectMCPEnvFileFormat(path string) (string, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return mcpEnvFormatDotenv, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("output_refused: existing environment file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("output_refused: existing environment file is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil || currentErr != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return "", errors.New("output_refused: existing environment file changed during inspection")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64*1024))
	if err != nil {
		return "", errors.New("output_refused: existing environment file is unavailable")
	}
	defer wipe(data)
	return classifyMCPEnvFileFormat(data, filepath.Base(path))
}

type mcpEnvFormatScores struct {
	dotenv  int
	docker  int
	shell   int
	systemd int
}

func classifyMCPEnvFileFormat(data []byte, name string) (string, error) {
	marker := []byte(mcpEnvFormatMarker)
	scores := mcpEnvFormatScores{}
	for _, rawLine := range bytes.Split(data, []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, marker) {
			format := strings.TrimSpace(string(bytes.TrimPrefix(line, marker)))
			if format == mcpEnvFormatDotenv || format == mcpEnvFormatDocker || format == mcpEnvFormatShell || format == mcpEnvFormatSystemd {
				return format, nil
			}
			return "", errors.New("output_refused: existing environment file has an invalid Wipe.me format marker")
		}
		if bytes.HasPrefix(line, []byte("#!")) && shellShebang(line) {
			scores.shell += 100
			continue
		}
		if bytes.HasPrefix(line, []byte(";")) {
			scores.systemd += 80
			continue
		}
		if bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		if bytes.HasPrefix(line, []byte("export ")) {
			scores.shell += 100
			line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("export ")))
		}
		separator := bytes.IndexByte(line, '=')
		if separator <= 0 {
			continue
		}
		value := bytes.TrimSpace(line[separator+1:])
		if len(value) >= 2 && value[0] == '"' {
			if bytes.Contains(value, []byte("\\n")) || bytes.Contains(value, []byte("\\r")) || bytes.Contains(value, []byte("\\t")) {
				scores.dotenv += 20
			}
			if bytes.Contains(value, []byte("\\`")) {
				scores.systemd += 20
			}
		}
	}
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".docker.env"), strings.HasSuffix(name, ".env.docker"), strings.HasSuffix(name, ".docker"):
		scores.docker += 50
	case strings.HasSuffix(name, ".systemd.env"), strings.HasSuffix(name, ".env.systemd"), strings.HasSuffix(name, ".systemd"):
		scores.systemd += 50
	case strings.HasSuffix(name, ".sh"), strings.HasSuffix(name, ".bash"), strings.HasSuffix(name, ".zsh"):
		scores.shell += 50
	case name == ".env", strings.HasSuffix(name, ".dotenv"), strings.HasSuffix(name, ".env"):
		scores.dotenv += 10
	}
	return preferredMCPEnvFileFormat(scores), nil
}

func shellShebang(line []byte) bool {
	interpreter := strings.ToLower(string(line))
	return strings.Contains(interpreter, "/sh") || strings.Contains(interpreter, "/bash") || strings.Contains(interpreter, "/zsh") || strings.Contains(interpreter, "env sh") || strings.Contains(interpreter, "env bash") || strings.Contains(interpreter, "env zsh")
}

func preferredMCPEnvFileFormat(scores mcpEnvFormatScores) string {
	// dotenv is the stable tie-breaker because a plain NAME=value file belongs to
	// the shared subset of all four grammars. A different choice requires positive
	// syntax or filename evidence; parser success alone cannot distinguish intent.
	bestFormat, bestScore := mcpEnvFormatDotenv, scores.dotenv
	for _, candidate := range []struct {
		format string
		score  int
	}{
		{mcpEnvFormatDocker, scores.docker},
		{mcpEnvFormatShell, scores.shell},
		{mcpEnvFormatSystemd, scores.systemd},
	} {
		if candidate.score > bestScore {
			bestFormat, bestScore = candidate.format, candidate.score
		}
	}
	return bestFormat
}

func validateMCPEnvFileMappings(selectors []mcpEnvironmentSelector) ([]mcpEnvironmentMapping, error) {
	if len(selectors) == 0 || len(selectors) > 16 {
		return nil, errors.New("invalid_arguments: environment mappings count is outside the supported range")
	}
	seen := map[string]struct{}{}
	mappings := make([]mcpEnvironmentMapping, 0, len(selectors))
	for _, selector := range selectors {
		if !envName.MatchString(selector.Name) || strings.HasPrefix(selector.Name, "WIPEME_") {
			return nil, errors.New("invalid_arguments: invalid or protected environment name")
		}
		if _, duplicate := seen[selector.Name]; duplicate {
			return nil, errors.New("invalid_arguments: duplicate environment mapping")
		}
		seen[selector.Name] = struct{}{}
		block := -1
		if selector.Block != nil {
			if *selector.Block < 0 {
				return nil, errors.New("invalid_arguments: block index must be non-negative")
			}
			block = *selector.Block
		}
		mappings = append(mappings, mcpEnvironmentMapping{Name: selector.Name, Block: block})
	}
	return mappings, nil
}

func mappingsToSelectors(mappings []mcpEnvironmentMapping) []mcpEnvironmentSelector {
	selectors := make([]mcpEnvironmentSelector, 0, len(mappings))
	for _, mapping := range mappings {
		block := mapping.Block
		if block < 0 {
			selectors = append(selectors, mcpEnvironmentSelector{Name: mapping.Name})
		} else {
			selectors = append(selectors, mcpEnvironmentSelector{Name: mapping.Name, Block: &block})
		}
	}
	return selectors
}

func validateMCPEnvFileDestination(value string, overwrite bool, policy mcpPolicy) (string, error) {
	path, err := normalizeAbsolutePath(value)
	if err != nil || (policy.accessMode != mcpAccessHost && !pathWithinRoots(path, policy.allowedWriteRoots)) {
		return "", errors.New("path_outside_allowed_root: destination file is not allowed")
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !overwrite {
			return "", errors.New("output_refused: destination file already exists")
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("output_refused: destination file is unsafe")
		}
	} else if !os.IsNotExist(statErr) {
		return "", errors.New("output_refused: destination file is unavailable")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || (policy.accessMode != mcpAccessHost && !pathWithinRoots(parent, policy.allowedWriteRoots)) {
		return "", errors.New("path_outside_allowed_root: destination parent is not allowed")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return "", errors.New("output_refused: destination parent is unavailable")
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func materializeMCPEnvFileRecovery(record *mcpRecoveryRecord, options mcpEnvFileOptions) error {
	decrypted, err := decryptRecoveryRecord(record)
	if err != nil {
		return errMCPEnvCredentialRejected
	}
	defer wipeResult(&decrypted)
	values, err := selectMCPEnvironment(decrypted, options.mappings)
	if err != nil {
		return err
	}
	defer wipeEnvironmentValues(values)
	return materializeMCPEnvFile(options, values)
}

func materializeMCPGeneratedEnvFile(record *mcpRecoveryRecord, options mcpEnvFileOptions) error {
	values := make(map[string]string, len(options.mappings))
	for _, mapping := range options.mappings {
		values[mapping.Name] = record.GeneratedSecret
	}
	defer wipeEnvironmentValues(values)
	return materializeMCPEnvFile(options, values)
}

func materializeMCPEnvFile(options mcpEnvFileOptions, values map[string]string) error {
	encoded, err := encodeMCPEnvFile(options.format, options.mappings, values)
	if err != nil {
		return err
	}
	defer wipe(encoded)
	return writeAtomicPrivateFile(options.destination, encoded, options.overwrite)
}

func encodeMCPEnvFile(format string, mappings []mcpEnvironmentMapping, values map[string]string) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString(mcpEnvFormatMarker)
	output.WriteString(format)
	output.WriteByte('\n')
	for _, mapping := range mappings {
		value := values[mapping.Name]
		if strings.IndexByte(value, 0) >= 0 {
			wipe(output.Bytes())
			return nil, errors.New("output_refused: environment values cannot contain NUL")
		}
		switch format {
		case mcpEnvFormatDotenv:
			output.WriteString(mapping.Name)
			output.WriteString("=\"")
			for _, character := range value {
				switch character {
				case '\\', '"', '$':
					output.WriteByte('\\')
					output.WriteRune(character)
				case '\n':
					output.WriteString("\\n")
				case '\r':
					output.WriteString("\\r")
				case '\t':
					output.WriteString("\\t")
				default:
					output.WriteRune(character)
				}
			}
			output.WriteString("\"\n")
		case mcpEnvFormatDocker:
			if strings.ContainsAny(value, "\r\n") {
				wipe(output.Bytes())
				return nil, errors.New("output_refused: docker values cannot contain newlines; use dotenv, shell, or systemd format")
			}
			output.WriteString(mapping.Name)
			output.WriteByte('=')
			output.WriteString(value)
			output.WriteByte('\n')
		case mcpEnvFormatShell:
			output.WriteString("export ")
			output.WriteString(mapping.Name)
			output.WriteString("='")
			output.WriteString(strings.ReplaceAll(value, "'", "'\"'\"'"))
			output.WriteString("'\n")
		case mcpEnvFormatSystemd:
			output.WriteString(mapping.Name)
			output.WriteString("=\"")
			for _, character := range value {
				if strings.ContainsRune("\\\"`$", character) {
					output.WriteByte('\\')
				}
				output.WriteRune(character)
			}
			output.WriteString("\"\n")
		default:
			wipe(output.Bytes())
			return nil, errors.New("invalid_arguments: unsupported environment file format")
		}
	}
	return output.Bytes(), nil
}

func writeAtomicPrivateFile(path string, data []byte, overwrite bool) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".wipeme-env-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("write environment file")
	}
	if overwrite {
		if err := os.Rename(temporaryPath, path); err != nil {
			return err
		}
	} else {
		if err := os.Link(temporaryPath, path); err != nil {
			return err
		}
		if err := os.Remove(temporaryPath); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	complete = true
	return nil
}

func envFileFailure(ctx context.Context, record *mcpRecoveryRecord, handle string, store *mcpRecoveryStore, settings config, lease *mcpRecoveryLease) mcpEnvFileOutput {
	if record.Attempt < store.maxAttempts {
		return mcpEnvFileOutput{
			Status: "output_failed", Consumed: record.Type == "consume_env_file", RemoteMessageCreated: record.Type == "generate_env_file",
			DestinationFile: record.DestinationFile, Format: record.EnvFileFormat, Attempt: record.Attempt, Retryable: true, RecoveryHandle: handle,
			RetryUntil: record.ExpiresAt.Format(time.RFC3339), RecoveryDeleted: false,
		}
	}
	output := mcpEnvFileOutput{
		Status: "output_failed", Consumed: record.Type == "consume_env_file", RemoteMessageCreated: record.Type == "generate_env_file",
		DestinationFile: record.DestinationFile, Format: record.EnvFileFormat, Attempt: record.Attempt, Retryable: false, RecoveryDeleted: true,
	}
	if record.Type == "generate_env_file" {
		deleted, absent, err := deleteGeneratedRecoveryRemote(ctx, record, settings)
		if err != nil || (!deleted && !absent) {
			output.RecoveryDeleted = false
			output.RecoveryHandle = handle
			return output
		}
	}
	if lease != nil {
		if err := lease.delete(); err != nil {
			output.RecoveryDeleted = false
			output.RecoveryHandle = handle
		}
	} else if err := store.discard(handle); err != nil {
		output.RecoveryDeleted = false
		output.RecoveryHandle = handle
	}
	return output
}

func successfulConsumedEnvFileOutput(record *mcpRecoveryRecord, options mcpEnvFileOptions) mcpEnvFileOutput {
	return mcpEnvFileOutput{
		Status: "written", Consumed: true, DestinationFile: options.destination, Format: options.format, VariablesWritten: len(options.mappings),
		Attempt: record.Attempt, Retryable: false, RecoveryDeleted: true,
	}
}

func finalizeGeneratedEnvFile(record *mcpRecoveryRecord, options mcpEnvFileOptions, includeQR bool) (mcpEnvFileOutput, []byte) {
	output := mcpEnvFileOutput{
		Status: "written", RemoteMessageCreated: true, DestinationFile: options.destination, Format: options.format, VariablesWritten: len(options.mappings),
		Attempt: record.Attempt, Retryable: false, RecoveryDeleted: true, PrivateLink: record.PrivateLink,
		MessageID: record.MessageID, ExpiresAt: record.MessageExpiresAt,
	}
	if record.LinkFile != "" {
		linkData := []byte(record.PrivateLink + "\n")
		writeErr := writePrivate(record.LinkFile, linkData)
		wipe(linkData)
		if writeErr == nil {
			output.LinkFileWritten = true
		}
	}
	if record.ReceiptFile != "" {
		expiresAt, _ := time.Parse(time.RFC3339, record.MessageExpiresAt)
		receipt := creatorReceipt{CipherVersion: wipeme.ProtocolVersion, URL: record.PrivateLink, MessageID: record.MessageID, Secret: record.CreatorSecret, ExpiresAt: expiresAt}
		encoded, err := json.MarshalIndent(receipt, "", "  ")
		encoded = append(encoded, '\n')
		if err == nil && writePrivate(record.ReceiptFile, encoded) == nil {
			output.ReceiptWritten = true
		}
		wipe(encoded)
	}
	if includeQR {
		png, err := encodeMCPQRCode(record.PrivateLink)
		if err == nil {
			output.QRIncluded = true
			return output, png
		}
	}
	return output, nil
}

func envFileToolResponse(output mcpEnvFileOutput, png []byte, err error) (*mcpsdk.CallToolResult, mcpEnvFileOutput, error) {
	if err != nil || len(png) == 0 {
		return nil, output, err
	}
	encoded, marshalErr := json.Marshal(output)
	if marshalErr != nil {
		return nil, mcpEnvFileOutput{}, errors.New("internal_error: encode environment file result")
	}
	return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{
		&mcpsdk.TextContent{Text: string(encoded)},
		&mcpsdk.ImageContent{MIMEType: "image/png", Data: png, Annotations: &mcpsdk.Annotations{Audience: []mcpsdk.Role{mcpsdk.Role("user")}, Priority: 1}},
	}}, output, nil
}
