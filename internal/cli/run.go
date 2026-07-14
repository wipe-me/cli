// Package cli implements the wipeme command-line interface.
package cli

import (
	"context"
	"crypto/rand"
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

	"github.com/wipe-me/cli/internal/api"
	"github.com/wipe-me/cli/internal/base58"
	"github.com/wipe-me/cli/internal/clipboard"
	"github.com/wipe-me/cli/internal/envelope"
	"github.com/wipe-me/cli/internal/media"
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
		err = runDelete(args[1:], stdin, stdout, stderr, version)
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

	messageID, err := base58.RandomString(rand.Reader, 12)
	if err != nil {
		return fmt.Errorf("generate message ID: %w", err)
	}
	secret, err := base58.RandomString(rand.Reader, 16)
	if err != nil {
		return fmt.Errorf("generate link secret: %w", err)
	}
	temporary, err := os.CreateTemp("", "wipeme-*.wme")
	if err != nil {
		return fmt.Errorf("create encrypted temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure encrypted temporary file: %w", err)
	}
	encrypted, err := envelope.Write(temporary, messageID, message, secret, files, envelope.WriteOptions{})
	if err != nil {
		return err
	}
	defer wipe(encrypted.DeletionKey[:])
	info, err := temporary.Stat()
	if err != nil {
		return fmt.Errorf("inspect encrypted envelope: %w", err)
	}

	client := newAPIClient(settings.APIEndpoint, version)
	expiresAt := time.Now().Add(settings.Expires)
	created, err := client.Create(context.Background(), messageID, temporary, info.Size(), expiresAt, encrypted.DeletionKey[:])
	if err != nil {
		return err
	}
	link, err := buildLink(settings.SiteURL, messageID, secret)
	if err != nil {
		return err
	}
	if settings.Receipt != "" {
		receipt := creatorReceipt{CipherVersion: envelope.Version, URL: link, MessageID: messageID, Secret: secret, ExpiresAt: expiresAt}
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

func runDelete(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) error {
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
	deletionKey, err := envelope.DeriveDeletionKey(messageID, secret)
	if err != nil {
		return err
	}
	defer wipe(deletionKey[:])
	if err := newAPIClient(apiEndpoint, version).Delete(context.Background(), messageID, deletionKey[:]); err != nil {
		return err
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
		fmt.Fprintln(stderr, "Enter message, then press Ctrl-D:")
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
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + base58.Group(messageID, 4)
	parsed.RawQuery = ""
	parsed.Fragment = base58.Group(secret, 4)
	return parsed.String(), nil
}

func parsePrivateLink(privateLink string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(privateLink))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", fmt.Errorf("invalid private link")
	}
	path := strings.Trim(parsed.Path, "/")
	if separator := strings.LastIndexByte(path, '/'); separator >= 0 {
		path = path[separator+1:]
	}
	messageID, err := base58.Normalize(path, 12)
	if err != nil {
		return "", "", fmt.Errorf("invalid message ID in private link: %w", err)
	}
	secret, err := base58.Normalize(parsed.Fragment, 16)
	if err != nil {
		return "", "", fmt.Errorf("invalid secret in private link: %w", err)
	}
	return messageID, secret, nil
}

func newAPIClient(endpoint, version string) api.Client {
	return api.Client{
		Endpoint: endpoint,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Minute,
		},
		UserAgent: "wipeme/" + version,
	}
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
