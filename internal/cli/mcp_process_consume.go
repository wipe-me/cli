package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	passwordgen "github.com/wipe-me/cli/internal/password"
	"github.com/wipe-me/sdk/go/wipeme"
)

type mcpEnvironmentSelector struct {
	Name  string `json:"name"`
	Block *int   `json:"block,omitempty"`
}

type mcpEnvironmentMapping struct {
	Name  string `json:"name"`
	Block int    `json:"block"`
}

type consumeIntoProcessEnvInput struct {
	MCPLinkSource
	PassphraseSources []MCPPassphraseSource    `json:"passphrase_sources,omitempty"`
	Profile           string                   `json:"profile"`
	Arguments         []string                 `json:"arguments,omitempty"`
	Environment       []mcpEnvironmentSelector `json:"environment"`
}

type generateSecretIntoProcessEnvInput struct {
	MCPCreationControls
	Length          int      `json:"length,omitempty"`
	Chars           string   `json:"chars,omitempty"`
	Alphabet        string   `json:"alphabet,omitempty"`
	NoRequireEach   bool     `json:"no_require_each,omitempty"`
	Profile         string   `json:"profile"`
	Arguments       []string `json:"arguments,omitempty"`
	EnvironmentName string   `json:"environment_name"`
}

type retryProcessEnvInput struct {
	RecoveryHandle  string                   `json:"recovery_handle"`
	Arguments       []string                 `json:"arguments,omitempty"`
	Environment     []mcpEnvironmentSelector `json:"environment,omitempty"`
	EnvironmentName string                   `json:"environment_name,omitempty"`
	IncludeQR       bool                     `json:"include_qr,omitempty"`
}

type mcpProcessExecutionOutput struct {
	Status               string `json:"status"`
	Consumed             bool   `json:"consumed,omitempty"`
	RemoteMessageCreated bool   `json:"remote_message_created,omitempty"`
	Started              bool   `json:"started"`
	ExitCode             *int   `json:"exit_code,omitempty"`
	Signal               string `json:"signal,omitempty"`
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

type mcpProcessRun struct {
	status   string
	started  bool
	exitCode *int
	signal   string
}

func registerMCPProcessConsumptionTools(server *mcpsdk.Server, policy mcpPolicy, settings config, store *mcpRecoveryStore) {
	destructive, openWorld := true, true
	annotations := &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &openWorld}

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "consume_into_process_env",
		Title:       "Consume into an approved process",
		Description: "Consume a one-time message and inject selected text blocks into an administrator-approved process without returning plaintext or process output.",
		Annotations: annotations,
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input consumeIntoProcessEnvInput) (*mcpsdk.CallToolResult, mcpProcessExecutionOutput, error) {
		profile, err := validateMCPProfileCall(policy, input.Profile, "consumer", input.Arguments)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		mappings, err := validateMCPEnvironmentMappings(profile, input.Environment)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		privateLink, err := resolveMCPLinkValues(policy, input.PrivateLink, input.LinkFile, input.LinkEnv)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		application, err := wipeme.ParseApplicationPrivateLink(privateLink)
		privateLink = ""
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, errors.New("invalid_link: private link is invalid")
		}
		candidates, err := mcpCredentialCandidates(application, input.PassphraseSources, policy)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		defer wipeStrings(candidates)
		if len(candidates) == 0 {
			return nil, mcpProcessExecutionOutput{}, errors.New("credential_unavailable: no passphrase source is available")
		}
		client, err := newAPIClient(settings.APIEndpoint)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, errors.New("retrieval_failed: service configuration is invalid")
		}
		retrieved, err := client.RetrieveMessage(ctx, application.MessageID)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, sanitizedMCPRetrievalError(err)
		}
		record := &mcpRecoveryRecord{
			Type: "consume_process", Envelope: append([]byte(nil), retrieved.Envelope...), MessageID: application.MessageID,
			Secret: application.Secret, Manual: application.CustomPassphrase, Candidates: append([]string(nil), candidates...),
			Profile: input.Profile, Arguments: append([]string(nil), input.Arguments...), Environment: mappings, Attempt: 1,
		}
		handle, err := store.create(record)
		if err != nil {
			record.wipe()
			return nil, mcpProcessExecutionOutput{}, err
		}
		defer record.wipe()
		decrypted, err := decryptRecoveryRecord(record)
		if err != nil {
			_ = store.discard(handle)
			return nil, mcpProcessExecutionOutput{}, errors.New("credential_rejected: available credentials did not decrypt the message")
		}
		defer wipeResult(&decrypted)
		environment, err := selectMCPEnvironment(decrypted, mappings)
		if err != nil {
			return nil, pendingProcessOutput(record, handle, mcpProcessRun{status: "execution_failed"}, store), nil
		}
		defer wipeEnvironmentValues(environment)
		run := runMCPConsumer(ctx, profile, input.Arguments, environment)
		if run.status == "executed" {
			if err := store.discard(handle); err != nil {
				return nil, mcpProcessExecutionOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
			}
			return nil, completedConsumedProcessOutput(record.Attempt, run), nil
		}
		return nil, pendingProcessOutput(record, handle, run, store), nil
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "generate_secret_into_process_env",
		Title:       "Generate and inject a private secret",
		Description: "Generate one password, upload it, and inject the same value into an approved process. The private link is released only after an accepted process exit.",
		Annotations: annotations,
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input generateSecretIntoProcessEnvInput) (*mcpsdk.CallToolResult, mcpProcessExecutionOutput, error) {
		profile, err := validateMCPProfileCall(policy, input.Profile, "consumer", input.Arguments)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		if err := validateMCPEnvironmentName(profile, input.EnvironmentName); err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		linkPath, receiptPath, err := preflightMCPCreationOutputs(input.MCPCreationControls, policy)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		passphrase, manual, err := resolveMCPCreationPassphrase(input.PassphraseSource, policy)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		defer func() { passphrase = "" }()
		length := input.Length
		if length == 0 {
			length = passwordgen.DefaultLength
		}
		generated, err := passwordgen.Generate(passwordgen.Options{Length: length, Preset: input.Chars, Alphabet: input.Alphabet, NoRequireEach: input.NoRequireEach})
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, errors.New("invalid_arguments: invalid password generation options")
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
			return nil, mcpProcessExecutionOutput{}, err
		}
		application, err := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, errors.New("internal_error: retain generated capability")
		}
		candidate, creatorSecret := application.Secret, application.Secret
		if manual {
			candidate, creatorSecret = passphrase, passphrase
		}
		record := &mcpRecoveryRecord{
			Type: "generate_process", MessageID: application.MessageID, Secret: application.Secret, Manual: manual,
			Candidates: []string{candidate}, Profile: input.Profile, Arguments: append([]string(nil), input.Arguments...),
			EnvironmentName: input.EnvironmentName, GeneratedSecret: string(generated), PrivateLink: created.PrivateLink,
			MessageExpiresAt: created.ExpiresAt, AttachmentCount: created.AttachmentCount, CreatorSecret: creatorSecret,
			ReceiptFile: receiptPath, LinkFile: linkPath, Attempt: 1,
		}
		handle, err := store.create(record)
		if err != nil {
			_, _, _ = deleteGeneratedRecoveryRemote(ctx, record, settings)
			record.wipe()
			return nil, mcpProcessExecutionOutput{}, err
		}
		defer record.wipe()
		run := runMCPConsumer(ctx, profile, input.Arguments, map[string]string{input.EnvironmentName: string(generated)})
		if run.status != "executed" {
			if record.Attempt >= store.maxAttempts {
				deleted, absent, deleteErr := deleteGeneratedRecoveryRemote(ctx, record, settings)
				if deleteErr == nil && (deleted || absent) {
					if err := store.discard(handle); err != nil {
						return nil, mcpProcessExecutionOutput{}, errors.New("recovery_corrupt: exhausted recovery could not be removed")
					}
					return nil, terminalProcessFailure(record, run), nil
				}
				output := terminalProcessFailure(record, run)
				output.RecoveryDeleted = false
				output.RecoveryHandle = handle
				return nil, output, nil
			}
			return nil, pendingProcessOutput(record, handle, run, store), nil
		}
		if err := store.discard(handle); err != nil {
			return nil, mcpProcessExecutionOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		output, png := finalizeGeneratedProcess(record, run, input.IncludeQR)
		return processToolResponse(output, png, nil)
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "retry_process_env",
		Title:       "Retry an approved process",
		Description: "Retry a consumed-message or generated-secret process operation from protected local recovery without another retrieval or secret generation.",
		Annotations: annotations,
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input retryProcessEnvInput) (*mcpsdk.CallToolResult, mcpProcessExecutionOutput, error) {
		lease, record, err := store.acquire(input.RecoveryHandle)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		defer lease.release()
		defer record.wipe()
		if record.Type != "consume_process" && record.Type != "generate_process" {
			return nil, mcpProcessExecutionOutput{}, errors.New("recovery_unknown: recovery handle has the wrong operation type")
		}
		arguments := input.Arguments
		if arguments == nil {
			arguments = record.Arguments
		}
		profile, err := validateMCPProfileCall(policy, record.Profile, "consumer", arguments)
		if err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		record.Arguments = append([]string(nil), arguments...)
		record.Attempt++
		var environment map[string]string
		if record.Type == "consume_process" {
			mappings := record.Environment
			if input.Environment != nil {
				mappings, err = validateMCPEnvironmentMappings(profile, input.Environment)
				if err != nil {
					return nil, mcpProcessExecutionOutput{}, err
				}
				record.Environment = mappings
			}
			decrypted, decryptErr := decryptRecoveryRecord(record)
			if decryptErr != nil {
				_ = lease.delete()
				return nil, mcpProcessExecutionOutput{}, errors.New("recovery_corrupt: recovery record cannot decrypt the message")
			}
			defer wipeResult(&decrypted)
			environment, err = selectMCPEnvironment(decrypted, mappings)
			if err != nil {
				return nil, mcpProcessExecutionOutput{}, err
			}
		} else {
			name := record.EnvironmentName
			if input.EnvironmentName != "" {
				name = input.EnvironmentName
			}
			if err := validateMCPEnvironmentName(profile, name); err != nil {
				return nil, mcpProcessExecutionOutput{}, err
			}
			record.EnvironmentName = name
			environment = map[string]string{name: record.GeneratedSecret}
		}
		defer wipeEnvironmentValues(environment)
		if err := lease.save(record); err != nil {
			return nil, mcpProcessExecutionOutput{}, err
		}
		run := runMCPConsumer(ctx, profile, arguments, environment)
		if run.status != "executed" {
			if record.Type == "generate_process" && record.Attempt >= store.maxAttempts {
				deleted, absent, deleteErr := deleteGeneratedRecoveryRemote(ctx, record, settings)
				if deleteErr == nil && (deleted || absent) {
					_ = lease.delete()
					return nil, terminalProcessFailure(record, run), nil
				}
				output := terminalProcessFailure(record, run)
				output.RecoveryDeleted = false
				output.RecoveryHandle = input.RecoveryHandle
				return nil, output, nil
			}
			return nil, pendingProcessOutputWithLease(record, input.RecoveryHandle, run, store, lease), nil
		}
		if err := lease.delete(); err != nil {
			return nil, mcpProcessExecutionOutput{}, errors.New("recovery_corrupt: completed recovery could not be removed")
		}
		if record.Type == "generate_process" {
			output, png := finalizeGeneratedProcess(record, run, input.IncludeQR)
			return processToolResponse(output, png, nil)
		}
		return nil, completedConsumedProcessOutput(record.Attempt, run), nil
	})
}

func validateMCPEnvironmentMappings(profile mcpResolvedProcessProfile, selectors []mcpEnvironmentSelector) ([]mcpEnvironmentMapping, error) {
	if len(selectors) == 0 || len(selectors) > 16 {
		return nil, errors.New("invalid_arguments: environment mappings count is outside the supported range")
	}
	seen := map[string]struct{}{}
	mappings := make([]mcpEnvironmentMapping, 0, len(selectors))
	for _, selector := range selectors {
		if err := validateMCPEnvironmentName(profile, selector.Name); err != nil {
			return nil, err
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

func validateMCPEnvironmentName(profile mcpResolvedProcessProfile, name string) error {
	if !envName.MatchString(name) || strings.HasPrefix(name, "WIPEME_") {
		return errors.New("invalid_arguments: invalid or protected environment name")
	}
	if _, allowed := profile.allowedSecretEnv[name]; !allowed {
		return errors.New("profile_argument_rejected: environment name is not allowed by the process profile")
	}
	return nil
}

func selectMCPEnvironment(result wipeme.DecryptResult, mappings []mcpEnvironmentMapping) (map[string]string, error) {
	document := parseDocument(result.Manifest.Message)
	environment := make(map[string]string, len(mappings))
	for _, mapping := range mappings {
		value, ok := selectText(document, mapping.Block)
		if !ok {
			wipeEnvironmentValues(environment)
			return nil, errors.New("output_refused: selected message block does not contain text")
		}
		environment[mapping.Name] = value
	}
	return environment, nil
}

func runMCPConsumer(parent context.Context, profile mcpResolvedProcessProfile, arguments []string, secrets map[string]string) mcpProcessRun {
	ctx, cancel := context.WithTimeout(parent, profile.timeout)
	defer cancel()
	argv := append(append([]string(nil), profile.fixedArgs...), arguments...)
	command := exec.CommandContext(ctx, profile.executable, argv...)
	command.Dir = profile.workingDirectory
	environment := minimalMCPEnvironment(profile.inheritEnv)
	for name, value := range secrets {
		environment = removeEnv(environment, name)
		environment = append(environment, name+"="+value)
	}
	command.Env = environment
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return mcpProcessRun{status: "launch_failed", started: false}
	}
	err := command.Wait()
	run := mcpProcessRun{status: "executed", started: true}
	if ctx.Err() != nil {
		run.status = "timed_out"
		return run
	}
	exitCode := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			run.status = "execution_failed"
			return run
		}
		exitCode = exit.ExitCode()
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			run.status = "signaled"
			run.signal = status.Signal().String()
			return run
		}
	}
	run.exitCode = &exitCode
	if _, accepted := profile.acceptedExitCodes[exitCode]; !accepted {
		run.status = "execution_failed"
	}
	return run
}

func pendingProcessOutput(record *mcpRecoveryRecord, handle string, run mcpProcessRun, store *mcpRecoveryStore) mcpProcessExecutionOutput {
	if record.Attempt >= store.maxAttempts {
		output := terminalProcessFailure(record, run)
		if err := store.discard(handle); err != nil {
			output.RecoveryDeleted = false
			output.RecoveryHandle = handle
		}
		return output
	}
	return retryableProcessFailure(record, handle, run)
}

func pendingProcessOutputWithLease(record *mcpRecoveryRecord, handle string, run mcpProcessRun, store *mcpRecoveryStore, lease *mcpRecoveryLease) mcpProcessExecutionOutput {
	if record.Attempt >= store.maxAttempts {
		_ = lease.delete()
		return terminalProcessFailure(record, run)
	}
	return retryableProcessFailure(record, handle, run)
}

func retryableProcessFailure(record *mcpRecoveryRecord, handle string, run mcpProcessRun) mcpProcessExecutionOutput {
	return mcpProcessExecutionOutput{
		Status: run.status, Consumed: record.Type == "consume_process", RemoteMessageCreated: record.Type == "generate_process",
		Started: run.started, ExitCode: run.exitCode, Signal: run.signal, Attempt: record.Attempt,
		Retryable: true, RecoveryHandle: handle, RetryUntil: record.ExpiresAt.Format(time.RFC3339), RecoveryDeleted: false,
	}
}

func terminalProcessFailure(record *mcpRecoveryRecord, run mcpProcessRun) mcpProcessExecutionOutput {
	return mcpProcessExecutionOutput{
		Status: run.status, Consumed: record.Type == "consume_process", RemoteMessageCreated: record.Type == "generate_process",
		Started: run.started, ExitCode: run.exitCode, Signal: run.signal, Attempt: record.Attempt,
		Retryable: false, RecoveryDeleted: true,
	}
}

func completedConsumedProcessOutput(attempt int, run mcpProcessRun) mcpProcessExecutionOutput {
	return mcpProcessExecutionOutput{Status: "executed", Consumed: true, Started: true, ExitCode: run.exitCode, Attempt: attempt, Retryable: false, RecoveryDeleted: true}
}

func finalizeGeneratedProcess(record *mcpRecoveryRecord, run mcpProcessRun, includeQR bool) (mcpProcessExecutionOutput, []byte) {
	output := mcpProcessExecutionOutput{
		Status: "executed", RemoteMessageCreated: true, Started: true, ExitCode: run.exitCode, Attempt: record.Attempt,
		Retryable: false, RecoveryDeleted: true, PrivateLink: record.PrivateLink, MessageID: record.MessageID, ExpiresAt: record.MessageExpiresAt,
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

func processToolResponse(output mcpProcessExecutionOutput, png []byte, err error) (*mcpsdk.CallToolResult, mcpProcessExecutionOutput, error) {
	if err != nil || len(png) == 0 {
		return nil, output, err
	}
	encoded, marshalErr := json.Marshal(output)
	if marshalErr != nil {
		return nil, mcpProcessExecutionOutput{}, errors.New("internal_error: encode process result")
	}
	return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{
		&mcpsdk.TextContent{Text: string(encoded)},
		&mcpsdk.ImageContent{MIMEType: "image/png", Data: png, Annotations: &mcpsdk.Annotations{Audience: []mcpsdk.Role{mcpsdk.Role("user")}, Priority: 1}},
	}}, output, nil
}

func wipeEnvironmentValues(values map[string]string) {
	for name := range values {
		values[name] = ""
	}
}

func sanitizedMCPRetrievalError(err error) error {
	if api, ok := wipeme.AsAPIError(err); ok && (api.StatusCode == 404 || api.StatusCode == 410) {
		return errors.New("message_unavailable: message is unavailable or already consumed")
	}
	return errors.New("retrieval_failed: service request failed")
}
