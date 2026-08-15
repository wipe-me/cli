package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/cli/internal/media"
)

type mcpProducerOutput struct {
	Mode     string `json:"mode"`
	Filename string `json:"filename,omitempty"`
	MIMEType string `json:"mime_type,omitempty"`
}

type createFromProcessOutputInput struct {
	MCPCreationControls
	Profile         string            `json:"profile"`
	Arguments       []string          `json:"arguments,omitempty"`
	StdinFile       string            `json:"stdin_file,omitempty"`
	Output          mcpProducerOutput `json:"output"`
	AttachmentPaths []string          `json:"attachment_paths,omitempty"`
}

func registerMCPProducerTool(server *mcpsdk.Server, policy mcpPolicy, settings config) {
	destructive, openWorld := true, true
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "create_from_process_output",
		Title:       "Create from approved process output",
		Description: "Run an administrator-approved producer profile and encrypt its stdout without returning process output or message plaintext.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &destructive,
			IdempotentHint:  false,
			OpenWorldHint:   &openWorld,
		},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input createFromProcessOutputInput) (*mcpsdk.CallToolResult, mcpCreationResult, error) {
		profile, err := validateMCPProfileCall(policy, input.Profile, "producer", input.Arguments)
		if err != nil {
			return nil, mcpCreationResult{}, err
		}
		if input.Output.Mode != "text" && input.Output.Mode != "attachment" {
			return nil, mcpCreationResult{}, errors.New("invalid_arguments: output mode must be text or attachment")
		}
		if input.Output.Mode == "text" && (input.Output.Filename != "" || input.Output.MIMEType != "") {
			return nil, mcpCreationResult{}, errors.New("invalid_arguments: text output does not accept filename or mime_type")
		}
		if input.Output.Mode == "attachment" {
			if !validMCPAttachmentName(input.Output.Filename) {
				return nil, mcpCreationResult{}, errors.New("invalid_arguments: attachment output requires a safe filename")
			}
			if input.Output.MIMEType != "" {
				if parsed, _, parseErr := mime.ParseMediaType(input.Output.MIMEType); parseErr != nil || !strings.Contains(parsed, "/") {
					return nil, mcpCreationResult{}, errors.New("invalid_arguments: attachment output has an invalid MIME type")
				}
			}
		}
		stdinPath := ""
		if input.StdinFile != "" {
			stdinPath, err = validateMCPReadFile(input.StdinFile, policy.allowedReadRoots)
			if err != nil {
				return nil, mcpCreationResult{}, fmt.Errorf("%w: producer stdin file is unavailable", err)
			}
		}
		files, cleanup, err := prepareMCPAttachments(input.AttachmentPaths, policy.allowedReadRoots)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			return nil, mcpCreationResult{}, err
		}
		if _, _, err := preflightMCPCreationOutputs(input.MCPCreationControls, policy.allowedWriteRoots); err != nil {
			return nil, mcpCreationResult{}, err
		}

		captured, err := runMCPProducer(ctx, profile, input.Arguments, stdinPath)
		if err != nil {
			return nil, mcpCreationResult{}, err
		}
		defer wipe(captured)
		message := ""
		if input.Output.Mode == "text" {
			message, err = encodeTextBlocks([]string{string(captured)})
			if err != nil {
				return nil, mcpCreationResult{}, errors.New("internal_error: prepare producer output")
			}
		} else {
			produced, producedCleanup, prepareErr := prepareMCPProducedAttachment(captured, input.Output)
			if producedCleanup != nil {
				defer producedCleanup()
			}
			if prepareErr != nil {
				return nil, mcpCreationResult{}, prepareErr
			}
			files = append([]media.File{produced}, files...)
		}
		result, png, err := createMCPMessage(ctx, policy, settings, mcpCreateRequest{
			controls: input.MCPCreationControls,
			message:  message,
			files:    files,
			progress: mcpProgress(ctx, request),
		})
		return creationToolResponse(result, png, err)
	})
}

func validateMCPProfileCall(policy mcpPolicy, name, role string, arguments []string) (mcpResolvedProcessProfile, error) {
	profile, ok := policy.processProfiles[name]
	if !ok {
		return mcpResolvedProcessProfile{}, errors.New("profile_unknown: process profile is not configured")
	}
	if profile.role != role {
		return mcpResolvedProcessProfile{}, errors.New("profile_unknown: process profile has the wrong role")
	}
	if len(arguments) > profile.maxArguments {
		return mcpResolvedProcessProfile{}, errors.New("profile_argument_rejected: too many process arguments")
	}
	for _, argument := range arguments {
		accepted := false
		for _, pattern := range profile.argumentPatterns {
			if pattern.MatchString(argument) {
				accepted = true
				break
			}
		}
		if !accepted {
			return mcpResolvedProcessProfile{}, errors.New("profile_argument_rejected: process argument is not allowed")
		}
	}
	info, err := os.Lstat(profile.executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return mcpResolvedProcessProfile{}, errors.New("profile_unavailable: process executable is unavailable")
	}
	if profile.workingDirectory != "" {
		info, err := os.Stat(profile.workingDirectory)
		if err != nil || !info.IsDir() {
			return mcpResolvedProcessProfile{}, errors.New("profile_unavailable: process working directory is unavailable")
		}
	}
	return profile, nil
}

func runMCPProducer(parent context.Context, profile mcpResolvedProcessProfile, arguments []string, stdinPath string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, profile.timeout)
	defer cancel()
	argv := append(append([]string(nil), profile.fixedArgs...), arguments...)
	command := exec.CommandContext(ctx, profile.executable, argv...)
	command.Dir = profile.workingDirectory
	command.Env = minimalMCPEnvironment(profile.inheritEnv)
	command.Stderr = io.Discard
	if stdinPath != "" {
		handle, err := os.Open(stdinPath)
		if err != nil {
			return nil, errors.New("profile_unavailable: producer stdin is unavailable")
		}
		defer handle.Close()
		command.Stdin = handle
	}
	output := &mcpLimitedBuffer{limit: profile.maxStdoutBytes}
	command.Stdout = output
	err := command.Run()
	if output.exceeded {
		wipe(output.Bytes())
		return nil, errors.New("output_limit_exceeded: producer output exceeded its configured limit")
	}
	if ctx.Err() != nil {
		wipe(output.Bytes())
		return nil, errors.New("producer_failed: producer timed out")
	}
	exitCode := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			wipe(output.Bytes())
			return nil, errors.New("producer_failed: producer could not be started")
		}
		exitCode = exit.ExitCode()
	}
	if _, accepted := profile.acceptedExitCodes[exitCode]; !accepted {
		wipe(output.Bytes())
		return nil, errors.New("producer_failed: producer returned an unaccepted exit status")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

func minimalMCPEnvironment(names []string) []string {
	environment := make([]string, 0, len(names))
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

type mcpLimitedBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (buffer *mcpLimitedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - int64(buffer.Len())
	if remaining <= 0 {
		buffer.exceeded = true
		return 0, errors.New("output limit exceeded")
	}
	if int64(len(value)) > remaining {
		_, _ = buffer.Buffer.Write(value[:remaining])
		buffer.exceeded = true
		return int(remaining), errors.New("output limit exceeded")
	}
	return buffer.Buffer.Write(value)
}

func prepareMCPProducedAttachment(data []byte, output mcpProducerOutput) (media.File, func(), error) {
	handle, err := os.CreateTemp("", "wipeme-mcp-producer-*")
	if err != nil {
		return media.File{}, nil, errors.New("internal_error: stage producer attachment")
	}
	path := handle.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := handle.Chmod(0o600); err != nil {
		_ = handle.Close()
		cleanup()
		return media.File{}, nil, errors.New("internal_error: stage producer attachment")
	}
	_, writeErr := handle.Write(data)
	closeErr := handle.Close()
	if writeErr != nil || closeErr != nil {
		cleanup()
		return media.File{}, nil, errors.New("internal_error: stage producer attachment")
	}
	file, err := media.Inspect(path, output.Filename, output.MIMEType)
	if err != nil {
		cleanup()
		return media.File{}, nil, errors.New("output_refused: producer attachment is invalid")
	}
	sanitized, sanitizeCleanup, err := sanitizeAttachments([]media.File{file})
	if err != nil {
		cleanup()
		return media.File{}, nil, errors.New("output_refused: producer attachment privacy cleanup failed")
	}
	return sanitized[0], func() {
		sanitizeCleanup()
		cleanup()
	}, nil
}

func validMCPAttachmentName(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, `/\\`)
}
