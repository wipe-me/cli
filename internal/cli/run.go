// Package cli implements the wipeme command-line interface.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wipe-me/cli/internal/clipboard"
	"github.com/wipe-me/cli/internal/media"
	"github.com/wipe-me/sdk/go/wipeme"
)

const (
	defaultAPI  = "https://wipe.me/api/messages"
	defaultSite = "https://wipe.me"
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type durationValue struct{ target *time.Duration }

func (value durationValue) String() string {
	if value.target == nil {
		return ""
	}
	return value.target.String()
}
func (value durationValue) Set(input string) error {
	if strings.HasSuffix(input, "d") && strings.Count(input, "d") == 1 {
		days, err := strconv.ParseFloat(strings.TrimSuffix(input, "d"), 64)
		if err != nil || days <= 0 {
			return fmt.Errorf("invalid day duration %q", input)
		}
		*value.target = time.Duration(days * float64(24*time.Hour))
		return nil
	}
	parsed, err := time.ParseDuration(input)
	if err != nil {
		return err
	}
	*value.target = parsed
	return nil
}

type config struct {
	APIEndpoint string
	SiteURL     string
	Expires     time.Duration
	Message     string
	MessageFile string
	Attachments stringList
	StdinName   string
	StdinType   string
	JSON        bool
	Copy        bool
	Receipt     string
	ShowVersion bool
}

type jsonOutput struct {
	URL       string    `json:"url"`
	MessageID string    `json:"message_id"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Created   bool      `json:"created"`
}

type creatorReceipt struct {
	CipherVersion int       `json:"cipher_version"`
	URL           string    `json:"url"`
	MessageID     string    `json:"message_id"`
	Secret        string    `json:"secret"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Run executes the CLI and returns a process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	var err error
	if len(args) > 0 && args[0] == "delete" {
		err = runDelete(args[1:], stdin, stdout, stderr)
	} else {
		err = run(args, stdin, stdout, stderr, version)
	}
	if err != nil {
		fmt.Fprintf(stderr, "wipeme: %v\n", err)
		return 1
	}
	return 0
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) error {
	settings, paths, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if settings.ShowVersion {
		fmt.Fprintf(stdout, "wipeme %s\n", version)
		return nil
	}
	if settings.JSON && settings.Copy {
		return fmt.Errorf("--json and --copy cannot be used together")
	}
	paths = append(paths, settings.Attachments...)

	message, stagedStdin, cleanup, err := collectInput(stdin, stderr, settings, &paths)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	if message == "" && len(paths) == 0 {
		return fmt.Errorf("provide a message on stdin or at least one attachment")
	}

	files := make([]media.File, 0, len(paths))
	for _, path := range paths {
		name, contentType := "", ""
		if stagedStdin != "" && path == stagedStdin {
			name, contentType = settings.StdinName, settings.StdinType
		}
		file, err := media.Inspect(path, name, contentType)
		if err != nil {
			return err
		}
		files = append(files, file)
	}

	messageID, err := wipeme.GenerateMessageID()
	if err != nil {
		return fmt.Errorf("generate message ID: %w", err)
	}
	secret, err := wipeme.GenerateSecret()
	if err != nil {
		return fmt.Errorf("generate link secret: %w", err)
	}
	attachments, closeAttachments, err := openAttachments(files)
	if err != nil {
		return err
	}
	defer closeAttachments()
	progress := interactiveProgress(stderr, settings.JSON)
	var envelope bytes.Buffer
	encrypted, err := wipeme.EncryptWithOptions(&envelope, messageID, secret, message, attachments, wipeme.CryptoOptions{Progress: progress})
	if err != nil {
		return err
	}
	defer wipe(encrypted.DeletionKey[:])

	client, err := newAPIClient(settings.APIEndpoint)
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(settings.Expires)
	created, err := client.CreateMessage(context.Background(), wipeme.CreateMessageRequest{
		MessageID:   messageID,
		Envelope:    envelope.Bytes(),
		ContentHash: encrypted.ContentHash,
		DeletionKey: encrypted.DeletionKeyHeader,
		ExpiresAt:   expiresAt,
		Progress:    progress,
	})
	if err != nil {
		return err
	}
	link, err := buildLink(settings.SiteURL, messageID, secret)
	if err != nil {
		return err
	}
	if settings.Receipt != "" {
		receipt := creatorReceipt{CipherVersion: wipeme.ProtocolVersion, URL: link, MessageID: messageID, Secret: secret, ExpiresAt: expiresAt}
		if err := writeReceipt(settings.Receipt, receipt); err != nil {
			return fmt.Errorf("message was created at %s, but the creator receipt could not be saved: %w", link, err)
		}
	}

	if settings.Copy {
		if err := clipboard.Write(link); err != nil {
			return err
		}
		fmt.Fprintln(stderr, "One-time link copied to the clipboard.")
		return nil
	}
	if settings.JSON {
		return json.NewEncoder(stdout).Encode(jsonOutput{URL: link, MessageID: messageID, ExpiresAt: expiresAt, Created: created.Created})
	}
	_, err = fmt.Fprintln(stdout, link)
	return err
}

func interactiveProgress(stderr io.Writer, jsonMode bool) wipeme.ProgressFunc {
	file, ok := stderr.(*os.File)
	if jsonMode || !ok {
		return nil
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	return func(event wipeme.Progress) {
		label := strings.ToUpper(event.Phase[:1]) + event.Phase[1:]
		fmt.Fprintf(stderr, "\r%s %d%%", label, event.Percent)
		if event.Percent == 100 {
			fmt.Fprintln(stderr)
		}
	}
}

func parseFlags(args []string, stderr io.Writer) (config, []string, error) {
	settings := config{
		APIEndpoint: envOrDefault("WIPEME_API_URL", defaultAPI),
		SiteURL:     envOrDefault("WIPEME_SITE_URL", defaultSite),
		Expires:     24 * time.Hour,
	}
	flags := flag.NewFlagSet("wipeme", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&settings.APIEndpoint, "api-url", settings.APIEndpoint, "wipe.me create-message API endpoint")
	flags.StringVar(&settings.SiteURL, "site-url", settings.SiteURL, "public wipe.me site URL")
	flags.Var(durationValue{target: &settings.Expires}, "expires", "unopened-message expiration (for example 1h or 7d)")
	flags.StringVar(&settings.Message, "message", "", "message text (stdin is safer for secrets)")
	flags.StringVar(&settings.MessageFile, "message-file", "", "read message text from a file")
	flags.Var(&settings.Attachments, "attach", "attach a file; repeatable, or use - for stdin")
	flags.StringVar(&settings.StdinName, "name", "stdin.bin", "filename when --attach - is used")
	flags.StringVar(&settings.StdinType, "type", "", "MIME type override when --attach - is used")
	flags.BoolVar(&settings.JSON, "json", false, "print structured JSON")
	flags.BoolVar(&settings.Copy, "copy", false, "copy the link instead of printing it")
	flags.StringVar(&settings.Receipt, "receipt", "", "save a mode-0600 creator receipt; refuses to overwrite")
	flags.BoolVar(&settings.ShowVersion, "version", false, "print the version")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wipeme [options] [file ...]")
		fmt.Fprint(stderr, "\nCreate a private, one-time link from stdin and optional attachments.\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return config{}, nil, err
	}
	if settings.Expires <= 0 {
		return config{}, nil, fmt.Errorf("--expires must be positive")
	}
	if settings.Message != "" && settings.MessageFile != "" {
		return config{}, nil, fmt.Errorf("--message and --message-file cannot be used together")
	}
	return settings, flags.Args(), nil
}

func runDelete(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("wipeme delete", flag.ContinueOnError)
	flags.SetOutput(stderr)
	apiEndpoint := envOrDefault("WIPEME_API_URL", defaultAPI)
	jsonResult := false
	flags.StringVar(&apiEndpoint, "api-url", apiEndpoint, "wipe.me message API endpoint")
	flags.BoolVar(&jsonResult, "json", false, "print structured JSON")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wipeme delete [options] [link]")
		fmt.Fprint(stderr, "\nDelete a message using its complete private link. If omitted, read the link from stdin.\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 1 {
		return fmt.Errorf("delete accepts at most one private link")
	}
	privateLink := ""
	if flags.NArg() == 1 {
		privateLink = flags.Arg(0)
	} else {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("read private link: %w", err)
		}
		privateLink = strings.TrimSpace(string(data))
	}
	messageID, secret, err := parsePrivateLink(privateLink)
	if err != nil {
		return err
	}
	deletionKey, err := wipeme.DeriveDeletionKey(messageID, secret)
	if err != nil {
		return err
	}
	defer wipe(deletionKey[:])
	client, err := newAPIClient(apiEndpoint)
	if err != nil {
		return err
	}
	deleted, err := client.DeleteMessage(context.Background(), messageID, wipeme.DeletionKeyHeader(deletionKey))
	if err != nil {
		return err
	}
	if !deleted.Deleted {
		return fmt.Errorf("API returned an invalid deletion response")
	}
	if jsonResult {
		return json.NewEncoder(stdout).Encode(map[string]any{"deleted": true, "message_id": messageID})
	}
	_, err = fmt.Fprintln(stdout, "Deleted.")
	return err
}

func collectInput(stdin io.Reader, stderr io.Writer, settings config, paths *[]string) (string, string, func(), error) {
	stdinAttachment := -1
	for i, path := range *paths {
		if path == "-" {
			if stdinAttachment >= 0 {
				return "", "", nil, fmt.Errorf("stdin can only be attached once")
			}
			stdinAttachment = i
		}
	}
	if stdinAttachment >= 0 {
		if settings.Message != "" || settings.MessageFile != "" {
			return "", "", nil, fmt.Errorf("stdin cannot be both an attachment and a message")
		}
		temporary, err := os.CreateTemp("", "wipeme-stdin-*")
		if err != nil {
			return "", "", nil, fmt.Errorf("stage stdin attachment: %w", err)
		}
		path := temporary.Name()
		cleanup := func() { _ = os.Remove(path) }
		if err := temporary.Chmod(0o600); err != nil {
			_ = temporary.Close()
			cleanup()
			return "", "", nil, err
		}
		if _, err := io.Copy(temporary, stdin); err != nil {
			_ = temporary.Close()
			cleanup()
			return "", "", nil, fmt.Errorf("read stdin attachment: %w", err)
		}
		if err := temporary.Close(); err != nil {
			cleanup()
			return "", "", nil, err
		}
		(*paths)[stdinAttachment] = path
		return "", path, cleanup, nil
	}
	if settings.Message != "" {
		return settings.Message, "", nil, nil
	}
	if settings.MessageFile != "" {
		data, err := os.ReadFile(settings.MessageFile)
		if err != nil {
			return "", "", nil, fmt.Errorf("read message file: %w", err)
		}
		return string(data), "", nil, nil
	}
	if isTerminal(stdin) {
		if len(*paths) > 0 {
			return "", "", nil, nil
		}
		fmt.Fprintln(stderr, "Enter a private message. Press Ctrl-D on an empty line when finished:")
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", "", nil, fmt.Errorf("read message from stdin: %w", err)
	}
	return string(data), "", nil, nil
}

func buildLink(site, messageID, secret string) (string, error) {
	parsed, err := url.Parse(site)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid --site-url %q", site)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return wipeme.FormatPrivateLink(parsed.String(), messageID, secret)
}

func parsePrivateLink(privateLink string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(privateLink))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", fmt.Errorf("invalid private link")
	}
	messageID, secret, err := wipeme.ParsePrivateLink(privateLink)
	if err != nil {
		return "", "", fmt.Errorf("invalid private link: %w", err)
	}
	return messageID, secret, nil
}

func newAPIClient(endpoint string) (*wipeme.Client, error) {
	baseURL := strings.TrimSuffix(strings.TrimRight(endpoint, "/"), "/api/messages")
	return wipeme.NewClient(wipeme.ClientOptions{
		BaseURL:  baseURL,
		ClientID: "cli",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Minute,
		},
	})
}

func openAttachments(files []media.File) ([]wipeme.AttachmentInput, func(), error) {
	handles := make([]*os.File, 0, len(files))
	closeAll := func() {
		for _, handle := range handles {
			_ = handle.Close()
		}
	}
	attachments := make([]wipeme.AttachmentInput, 0, len(files))
	for _, file := range files {
		handle, err := os.Open(file.Path)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("open attachment %q: %w", file.Path, err)
		}
		handles = append(handles, handle)
		attachments = append(attachments, wipeme.AttachmentInput{
			Reader: handle,
			Name:   file.Name,
			Type:   file.Type,
			Kind:   file.Kind,
			Size:   file.Size,
			Width:  file.Width,
			Height: file.Height,
		})
	}
	return attachments, closeAll, nil
}

func writeReceipt(path string, receipt creatorReceipt) error {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = handle.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	encoder := json.NewEncoder(handle)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func isTerminal(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
