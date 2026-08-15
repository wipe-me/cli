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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wipe-me/cli/internal/clipboard"
	"github.com/wipe-me/cli/internal/media"
	passwordgen "github.com/wipe-me/cli/internal/password"
	"github.com/wipe-me/cli/internal/terminalqr"
	"github.com/wipe-me/sdk/go/wipeme"
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
	parsed, err := parseDuration(input)
	if err != nil {
		return err
	}
	*value.target = parsed
	return nil
}

type config struct {
	ServerURL      string
	APIEndpoint    string
	SiteURL        string
	ConfigPath     string
	APIConfigured  bool
	SiteConfigured bool
	MCP            *mcpYAMLConfig
	Expires        time.Duration
	Message        string
	MessageFile    string
	Attachments    stringList
	StdinName      string
	StdinType      string
	JSON           bool
	Copy           bool
	QR             bool
	QRBig          bool
	QRInvert       bool
	Receipt        string
	ShowVersion    bool
	GeneratePass   bool
	Length         int
	Chars          string
	Alphabet       string
	NoRequireEach  bool
	SetEnv         string
	LinkFile       string
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
	if len(args) > 0 && args[0] == "mcp" {
		err = runMCP(args[1:], stdin, stdout, stderr, version)
	} else if len(args) > 0 && (args[0] == "read" || args[0] == "exec") {
		err = runAccess(args[0], args[1:], stdin, stdout, stderr)
	} else if len(args) > 0 && args[0] == "delete" {
		err = runDelete(args[1:], stdin, stdout, stderr)
	} else {
		err = run(args, stdin, stdout, stderr, version)
	}
	if err != nil {
		fmt.Fprintf(stderr, "wipeme: %v\n", err)
		var coded *cliError
		if errors.As(err, &coded) {
			return coded.code
		}
		return 1
	}
	return 0
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) error {
	flagArgs, child := splitCommand(args)
	settings, paths, err := parseFlags(flagArgs, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fail(exitUsage, "%v", err)
	}
	if settings.ShowVersion {
		fmt.Fprintf(stdout, "wipeme %s\n", version)
		return nil
	}
	if settings.JSON && settings.Copy {
		return fmt.Errorf("--json and --copy cannot be used together")
	}
	if settings.JSON && settings.QR {
		return fail(exitUsage, "--json and --qr cannot be used together")
	}
	if settings.JSON && settings.QRBig {
		return fail(exitUsage, "--json and --qr-big cannot be used together")
	}
	if settings.QR && settings.QRBig {
		return fail(exitUsage, "--qr and --qr-big cannot be used together")
	}
	if settings.QRInvert && !settings.QR && !settings.QRBig {
		return fail(exitUsage, "--qr-invert requires --qr or --qr-big")
	}
	if len(child) > 0 && !settings.GeneratePass {
		return fail(exitUsage, "a child command requires --generate-pass")
	}
	if settings.SetEnv != "" && (len(child) == 0 || !settings.GeneratePass) {
		return fail(exitUsage, "--set-env requires --generate-pass and a command after --")
	}
	if len(child) > 0 && settings.JSON {
		return fail(exitUsage, "--json cannot be used with child execution")
	}
	if settings.GeneratePass && (settings.Message != "" || settings.MessageFile != "") {
		return fail(exitUsage, "--generate-pass cannot be combined with message input")
	}
	if settings.LinkFile != "" {
		if err := preflightOutput(accessOptions{output: settings.LinkFile}); err != nil {
			return err
		}
	}
	paths = append(paths, settings.Attachments...)

	message, stagedStdin, cleanup, err := collectInput(stdin, stderr, settings, &paths)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	var generated []byte
	if settings.GeneratePass {
		generated, err = passwordgen.Generate(passwordgen.Options{Length: settings.Length, Preset: settings.Chars, Alphabet: settings.Alphabet, NoRequireEach: settings.NoRequireEach})
		if err != nil {
			return err
		}
		defer wipe(generated)
		doc := map[string]any{"blocks": []any{map[string]any{"type": "paragraph", "data": map[string]any{"text": string(generated)}}}}
		encoded, _ := json.Marshal(doc)
		message = string(encoded)
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
	files, cleanupSanitized, err := sanitizeAttachments(files)
	if err != nil {
		return err
	}
	defer cleanupSanitized()
	message, err = addAttachmentBlocks(message, files)
	if err != nil {
		return err
	}

	manualPassphrase, manualMode := os.LookupEnv("WIPEME_PASSPHRASE")
	publicMessageID, publicSecret, messageID, secret := "", "", "", ""
	if manualMode {
		generatedID, generateErr := passwordgen.Generate(passwordgen.Options{Length: wipeme.CustomMessageIDLength, Alphabet: wipeme.Base58BTCAlphabet, NoRequireEach: true})
		if generateErr != nil {
			return fmt.Errorf("generate manual-passphrase message ID: %w", generateErr)
		}
		publicMessageID = string(generatedID)
		wipe(generatedID)
		messageID, secret, err = wipeme.DeriveCustomCryptoParameters(manualPassphrase, publicMessageID)
		if err != nil {
			return fmt.Errorf("WIPEME_PASSPHRASE: %w", err)
		}
	} else {
		publicMessageID, publicSecret, err = wipeme.GenerateApplicationCapabilities()
		if err != nil {
			return fmt.Errorf("generate message ID: %w", err)
		}
		application := wipeme.ApplicationLink{MessageID: publicMessageID, Secret: publicSecret}
		messageID, secret, err = application.EnvelopeCryptoParameters()
		if err != nil {
			return err
		}
	}
	attachments, closeAttachments, err := openAttachments(files)
	if err != nil {
		return err
	}
	defer closeAttachments()
	progress, finishProgress := interactiveProgress(stderr, settings.JSON)
	defer finishProgress()
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
		MessageID:   publicMessageID,
		Envelope:    envelope.Bytes(),
		ContentHash: encrypted.ContentHash,
		DeletionKey: encrypted.DeletionKeyHeader,
		ExpiresAt:   expiresAt,
		Progress:    progress,
	})
	if err != nil {
		return err
	}
	link := ""
	if manualMode {
		link, err = formatManualPrivateLink(settings.SiteURL, publicMessageID)
	} else {
		link, err = wipeme.FormatApplicationPrivateLink(settings.SiteURL, publicMessageID, publicSecret)
	}
	if err != nil {
		return err
	}
	if settings.Receipt != "" {
		receiptSecret := publicSecret
		if manualMode {
			receiptSecret = manualPassphrase
		}
		receipt := creatorReceipt{CipherVersion: wipeme.ProtocolVersion, URL: link, MessageID: publicMessageID, Secret: receiptSecret, ExpiresAt: expiresAt}
		if err := writeReceipt(settings.Receipt, receipt); err != nil {
			return fmt.Errorf("message was created at %s, but the creator receipt could not be saved: %w", link, err)
		}
	}
	if settings.LinkFile != "" {
		if err := writePrivate(settings.LinkFile, []byte(link+"\n")); err != nil {
			return fmt.Errorf("message was created but link file could not be saved: %w", err)
		}
	}

	if settings.Copy {
		if err := clipboard.Write(link); err != nil {
			return err
		}
		fmt.Fprintln(stderr, "One-time link copied to the clipboard.")
		return nil
	}
	if len(child) > 0 {
		if settings.LinkFile == "" && !settings.Copy {
			fmt.Fprintf(stderr, "Private link: %s\n", link)
			if err := writeQR(stderr, link, settings); err != nil {
				return err
			}
		}
		sel, err := validateSelectors(stringList{settings.SetEnv})
		if err != nil {
			return err
		}
		env := os.Environ()
		env = removeEnv(env, "WIPEME_PASSPHRASE")
		env = removeEnv(env, "WIPEME_PRIVATE_LINK")
		env = removeEnv(env, sel[0].name)
		env = append(env, sel[0].name+"="+string(generated))
		return runChild(child, stdin, stdout, stderr, env)
	}
	if settings.LinkFile != "" {
		return nil
	}
	if settings.JSON {
		return json.NewEncoder(stdout).Encode(jsonOutput{URL: link, MessageID: publicMessageID, ExpiresAt: expiresAt, Created: created.Created})
	}
	if _, err = fmt.Fprintln(stdout, link); err != nil {
		return err
	}
	return writeQR(stdout, link, settings)
}

const compactQRCaption = "Compact QR: requires a Unicode terminal with block-character support and a monospaced font; use --qr-big if distorted or unreadable."

func writeQR(writer io.Writer, link string, settings config) error {
	if settings.QR {
		if _, err := fmt.Fprintln(writer, compactQRCaption); err != nil {
			return err
		}
		return terminalqr.Write(writer, link, settings.QRInvert)
	}
	if settings.QRBig {
		return terminalqr.WriteBig(writer, link, settings.QRInvert)
	}
	return nil
}

func formatManualPrivateLink(site, messageID string) (string, error) {
	parsed, err := url.Parse(site)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid --site-url %q", site)
	}
	id, err := wipeme.NormalizeBase58(messageID, wipeme.CustomMessageIDLength)
	if err != nil {
		return "", err
	}
	grouped, _ := wipeme.GroupBase58(id, 4)
	parsed.RawQuery, parsed.Fragment = "", ""
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + grouped
	return parsed.String(), nil
}

func addAttachmentBlocks(message string, files []media.File) (string, error) {
	if len(files) == 0 {
		return message, nil
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(message), &document); err != nil || document["blocks"] == nil {
		document = map[string]any{}
		if message != "" {
			document["blocks"] = []any{map[string]any{"type": "paragraph", "data": map[string]any{"text": message}}}
		}
	}
	blocks, ok := document["blocks"].([]any)
	if !ok {
		blocks = nil
	}
	for index := range files {
		blocks = append(blocks, map[string]any{
			"type": "attachment",
			"data": map[string]any{"attachmentIndex": index},
		})
	}
	document["blocks"] = blocks
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("encode attachment document: %w", err)
	}
	return string(encoded), nil
}

const progressBarWidth = 12

type progressDisplay struct {
	writer    io.Writer
	active    bool
	lineWidth int
}

func interactiveProgress(stderr io.Writer, jsonMode bool) (wipeme.ProgressFunc, func()) {
	file, ok := stderr.(*os.File)
	if jsonMode || !ok {
		return nil, func() {}
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil, func() {}
	}
	display := &progressDisplay{writer: stderr}
	return display.update, display.finish
}

func (display *progressDisplay) update(event wipeme.Progress) {
	percent := event.Percent
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}
	filled := percent * progressBarWidth / 100
	bar := strings.Repeat("▰", filled) + strings.Repeat("▱", progressBarWidth-filled)
	line := fmt.Sprintf("%-13s %s %3d%%", progressLabel(event.Phase), bar, percent)
	width := utf8.RuneCountInString(line)
	padding := ""
	if display.lineWidth > width {
		padding = strings.Repeat(" ", display.lineWidth-width)
	}
	fmt.Fprintf(display.writer, "\r%s%s", line, padding)
	display.active = true
	display.lineWidth = width

	if event.Phase == "uploading" && percent == 100 {
		fmt.Fprintln(display.writer)
		display.active = false
		display.lineWidth = 0
	}
}

func (display *progressDisplay) finish() {
	if display.active {
		fmt.Fprintln(display.writer)
		display.active = false
		display.lineWidth = 0
	}
}

func progressLabel(phase string) string {
	switch phase {
	case "encrypting":
		return "Encrypting..."
	case "uploading":
		return "Uploading..."
	case "":
		return "Working..."
	default:
		return strings.ToUpper(phase[:1]) + phase[1:] + "..."
	}
}

func parseFlags(args []string, stderr io.Writer) (config, []string, error) {
	settings, err := loadBaseConfig(args)
	if err != nil {
		return config{}, nil, err
	}
	flags := flag.NewFlagSet("wipeme", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&settings.ConfigPath, "config", settings.ConfigPath, "configuration file (default: /etc/wipeme/config.yaml then ~/.wipeme/config.yaml)")
	flags.StringVar(&settings.ServerURL, "server-url", settings.ServerURL, "shared API and public site base URL")
	flags.StringVar(&settings.APIEndpoint, "api-url", settings.APIEndpoint, "wipe.me create-message API endpoint")
	flags.StringVar(&settings.SiteURL, "site-url", settings.SiteURL, "public wipe.me site URL")
	flags.Var(durationValue{target: &settings.Expires}, "expires", "unopened-message expiration (for example 1h or 7d)")
	flags.StringVar(&settings.Message, "message", "", "message text (stdin is safer for secrets)")
	flags.StringVar(&settings.MessageFile, "message-file", "", "read message text from a file")
	flags.Var(&settings.Attachments, "attach", "attach a file; repeatable, or use - for stdin")
	flags.StringVar(&settings.StdinName, "name", "stdin.bin", "filename when --attach - is used")
	flags.StringVar(&settings.StdinType, "type", "", "MIME type override when --attach - is used")
	flags.BoolVar(&settings.JSON, "json", false, "print structured JSON")
	flags.BoolVar(&settings.Copy, "copy", settings.Copy, "copy the link instead of printing it")
	flags.BoolVar(&settings.QR, "qr", false, "print a compact terminal QR code after the private link")
	flags.BoolVar(&settings.QRBig, "qr-big", false, "print a full-size terminal QR code as a compatibility fallback")
	flags.BoolVar(&settings.QRInvert, "qr-invert", false, "swap QR module colors (requires --qr or --qr-big)")
	flags.StringVar(&settings.Receipt, "receipt", "", "save a mode-0600 creator receipt; refuses to overwrite")
	flags.BoolVar(&settings.ShowVersion, "version", false, "print the version")
	flags.BoolVar(&settings.GeneratePass, "generate-pass", false, "securely generate a password as the first text block")
	flags.IntVar(&settings.Length, "length", passwordgen.DefaultLength, "generated password length")
	flags.StringVar(&settings.Chars, "chars", "", "portable, alnum, base58, base64url, hex, digits, letters, or ascii (default portable)")
	flags.StringVar(&settings.Alphabet, "alphabet", "", "exact custom printable ASCII alphabet")
	flags.BoolVar(&settings.NoRequireEach, "no-require-each", false, "disable applicable character-class requirements")
	flags.StringVar(&settings.SetEnv, "set-env", "", "inject generated password into child environment")
	flags.StringVar(&settings.LinkFile, "link-file", "", "save resulting private link in a mode-0600 file")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  wipeme [options] [file ...]")
		fmt.Fprintln(stderr, "  wipeme read [options] <private-link>")
		fmt.Fprintln(stderr, "  wipeme exec [options] <private-link> -- <command> [args...]")
		fmt.Fprintln(stderr, "  wipeme delete [options] [link]")
		fmt.Fprintln(stderr, "  wipeme mcp [options]")
		fmt.Fprint(stderr, "\nCreate a private, one-time link from stdin and optional attachments.\n\n")
		fmt.Fprintln(stderr, "Commands:")
		fmt.Fprintln(stderr, "  read      consume, decrypt, and output a private message")
		fmt.Fprintln(stderr, "  exec      consume and inject decrypted content into a child process")
		fmt.Fprintln(stderr, "  delete    permanently delete a message using its private link")
		fmt.Fprintln(stderr, "  mcp       run the restricted agent-safe MCP server over stdio")
		fmt.Fprintln(stderr, "\nOptions:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return config{}, nil, err
	}
	explicitFlags := make(map[string]bool)
	flags.Visit(func(item *flag.Flag) { explicitFlags[item.Name] = true })
	if explicitFlags["server-url"] {
		if !explicitFlags["api-url"] && !settings.APIConfigured {
			settings.APIEndpoint = settings.ServerURL
		}
		if !explicitFlags["site-url"] && !settings.SiteConfigured {
			settings.SiteURL = settings.ServerURL
		}
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
	settings, err := loadBaseConfig(args)
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("wipeme delete", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonResult := false
	o := accessOptions{}
	flags.StringVar(&settings.ConfigPath, "config", settings.ConfigPath, "configuration file (default: /etc/wipeme/config.yaml then ~/.wipeme/config.yaml)")
	flags.StringVar(&settings.ServerURL, "server-url", settings.ServerURL, "shared API and public site base URL")
	flags.StringVar(&settings.APIEndpoint, "api-url", settings.APIEndpoint, "wipe.me message API endpoint")
	flags.BoolVar(&jsonResult, "json", false, "print structured JSON")
	flags.StringVar(&o.linkFile, "link-file", "", "read the private link from a file")
	flags.StringVar(&o.linkEnv, "link-env", "", "read the private link from an environment variable")
	flags.StringVar(&o.passFile, "passphrase-file", "", "read a passphrase candidate from a file")
	flags.BoolVar(&o.passStdin, "passphrase-stdin", false, "read a passphrase candidate from stdin")
	flags.StringVar(&o.passEnv, "passphrase-env", "", "read a passphrase candidate from an environment variable")
	flags.BoolVar(&o.prompt, "passphrase-prompt", false, "include secure terminal prompting")
	flags.BoolVar(&o.nonInteractive, "non-interactive", envTruthy("WIPEME_NON_INTERACTIVE"), "never prompt")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wipeme delete [options] [link]")
		fmt.Fprint(stderr, "\nDelete a message using its complete private link. If omitted, read the link from stdin.\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fail(exitUsage, "%v", err)
	}
	explicitFlags := make(map[string]bool)
	flags.Visit(func(item *flag.Flag) { explicitFlags[item.Name] = true })
	if explicitFlags["server-url"] && !explicitFlags["api-url"] && !settings.APIConfigured {
		settings.APIEndpoint = settings.ServerURL
	}
	if flags.NArg() == 0 && o.linkFile == "" && o.linkEnv == "" && !o.passStdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("read private link: %w", err)
		}
		args = []string{strings.TrimSpace(string(data))}
	} else {
		args = flags.Args()
	}
	privateLink, err := resolveLink(args, o)
	if err != nil {
		return err
	}
	application, err := wipeme.ParseApplicationPrivateLink(privateLink)
	privateLink = ""
	if err != nil {
		return fail(exitLink, "invalid private link")
	}
	client, err := newAPIClient(settings.APIEndpoint)
	if err != nil {
		return err
	}
	deleted := false
	if !application.CustomPassphrase {
		messageID, secret, e := application.EnvelopeCryptoParameters()
		if e != nil {
			return fail(exitLink, "invalid private link")
		}
		deleted, e = deleteWithParameters(client, application.MessageID, messageID, secret)
		if e != nil {
			return e
		}
	} else {
		candidates, e := credentialCandidates(application, o, stdin)
		if e != nil {
			return e
		}
		defer wipeStrings(candidates)
		for _, candidate := range candidates {
			id, secret, e := wipeme.DeriveCustomCryptoParameters(candidate, application.MessageID)
			if e != nil {
				continue
			}
			deleted, e = deleteWithParameters(client, application.MessageID, id, secret)
			if deleted {
				break
			}
			if e != nil && !isCredentialAPIError(e) {
				return e
			}
		}
		if !deleted && !o.nonInteractive && (o.prompt || isTerminal(stdin)) {
			for i := 0; i < 3 && !deleted; i++ {
				candidate, e := readTTYPassphrase()
				if e != nil {
					break
				}
				id, secret, e := wipeme.DeriveCustomCryptoParameters(candidate, application.MessageID)
				candidate = ""
				if e != nil {
					continue
				}
				deleted, e = deleteWithParameters(client, application.MessageID, id, secret)
				if e != nil && !isCredentialAPIError(e) {
					return e
				}
			}
		}
		if !deleted {
			if len(candidates) == 0 {
				return fail(exitCredential, "no passphrase credential is available")
			}
			return fail(exitDecrypt, "available credentials did not authorize deletion")
		}
	}
	if !deleted {
		return fmt.Errorf("API returned an invalid deletion response")
	}
	if jsonResult {
		return json.NewEncoder(stdout).Encode(map[string]any{"deleted": true, "message_id": application.MessageID})
	}
	_, err = fmt.Fprintln(stdout, "Deleted.")
	return err
}

func deleteWithParameters(client *wipeme.Client, publicID, messageID, secret string) (bool, error) {
	key, err := wipeme.DeriveDeletionKey(messageID, secret)
	if err != nil {
		return false, err
	}
	defer wipe(key[:])
	result, err := client.DeleteMessage(context.Background(), publicID, wipeme.DeletionKeyHeader(key))
	if err != nil {
		return false, err
	}
	return result.Deleted, nil
}
func isCredentialAPIError(err error) bool {
	if api, ok := wipeme.AsAPIError(err); ok {
		return api.StatusCode == 401 || api.StatusCode == 403
	}
	return false
}

func collectInput(stdin io.Reader, stderr io.Writer, settings config, paths *[]string) (string, string, func(), error) {
	if settings.GeneratePass {
		for _, path := range *paths {
			if path == "-" {
				return "", "", nil, fmt.Errorf("--generate-pass conflicts with --attach -")
			}
		}
		if !isTerminal(stdin) {
			if f, ok := stdin.(*os.File); ok {
				if info, e := f.Stat(); e == nil && info.Mode()&os.ModeCharDevice == 0 {
					return "", "", nil, fmt.Errorf("--generate-pass cannot consume ordinary message stdin")
				}
			}
		}
		return "", "", nil, nil
	}
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

func sanitizeAttachments(files []media.File) ([]media.File, func(), error) {
	sanitized := make([]media.File, 0, len(files))
	cleanups := make([]func(), 0, len(files))
	cleanupAll := func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}
	for _, file := range files {
		privateFile, _, cleanup, err := media.SanitizeMetadata(file)
		if err != nil {
			cleanupAll()
			return nil, func() {}, err
		}
		cleanups = append(cleanups, cleanup)
		sanitized = append(sanitized, privateFile)
	}
	return sanitized, cleanupAll, nil
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
