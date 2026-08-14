package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/wipe-me/sdk/go/wipeme"
	"golang.org/x/term"
)

const (
	exitUsage      = 2
	exitLink       = 3
	exitCredential = 4
	exitDecrypt    = 5
	exitRetrieve   = 6
	exitOutput     = 8
	exitChild      = 9
)

type cliError struct {
	code int
	err  error
}

func (e *cliError) Error() string                  { return e.err.Error() }
func fail(code int, format string, a ...any) error { return &cliError{code, fmt.Errorf(format, a...)} }

type accessOptions struct {
	linkFile, linkEnv, passFile, passEnv, output, outputDir string
	passStdin, prompt, nonInteractive, json                 bool
	block                                                   int
	setEnv                                                  stringList
}

func runAccess(command string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	settings, err := loadBaseConfig(args)
	if err != nil {
		return err
	}
	before, child := splitCommand(args)
	f := flag.NewFlagSet("wipeme "+command, flag.ContinueOnError)
	f.SetOutput(stderr)
	o := accessOptions{block: -1}
	f.StringVar(&settings.ConfigPath, "config", settings.ConfigPath, "configuration file")
	f.StringVar(&settings.ServerURL, "server-url", settings.ServerURL, "shared API and site base URL")
	f.StringVar(&settings.APIEndpoint, "api-url", settings.APIEndpoint, "wipe.me API endpoint")
	f.StringVar(&o.linkFile, "link-file", "", "read the private link from a file")
	f.StringVar(&o.linkEnv, "link-env", "", "read the private link from an environment variable")
	f.StringVar(&o.passFile, "passphrase-file", "", "read a passphrase candidate from a file")
	f.BoolVar(&o.passStdin, "passphrase-stdin", false, "read a passphrase candidate from stdin")
	f.StringVar(&o.passEnv, "passphrase-env", "", "read a passphrase candidate from an environment variable")
	f.BoolVar(&o.prompt, "passphrase-prompt", false, "include secure terminal prompting")
	f.BoolVar(&o.nonInteractive, "non-interactive", envTruthy("WIPEME_NON_INTERACTIVE"), "never prompt")
	if command == "read" {
		f.BoolVar(&o.json, "json", false, "print structured decrypted JSON")
		f.IntVar(&o.block, "block", -1, "output one block by zero-based index")
		f.StringVar(&o.output, "output", "", "write selected content to a mode-0600 file")
		f.StringVar(&o.outputDir, "output-dir", "", "write attachments into a directory")
	} else {
		f.Var(&o.setEnv, "set-env", "environment NAME or NAME=block:N to inject; required")
	}
	f.Usage = func() { printAccessUsage(stderr, command); f.PrintDefaults() }
	if err := f.Parse(before); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fail(exitUsage, "%v", err)
	}
	explicit := map[string]bool{}
	f.Visit(func(x *flag.Flag) { explicit[x.Name] = true })
	if explicit["server-url"] && !explicit["api-url"] && !settings.APIConfigured {
		settings.APIEndpoint = settings.ServerURL
	}
	if command == "read" && len(child) > 0 {
		return fail(exitUsage, "read does not accept a child command")
	}
	if command == "exec" {
		if len(child) == 0 {
			return fail(exitUsage, "exec requires a command after --")
		}
		if len(o.setEnv) == 0 {
			return fail(exitUsage, "exec requires --set-env NAME")
		}
		if o.passStdin {
			return fail(exitUsage, "--passphrase-stdin conflicts with child stdin; use --passphrase-file or --passphrase-env")
		}
	}
	link, err := resolveLink(f.Args(), o)
	if err != nil {
		return err
	}
	parsed, err := wipeme.ParseApplicationPrivateLink(link)
	link = ""
	if err != nil {
		return fail(exitLink, "invalid private link")
	}
	selectors, err := validateSelectors(o.setEnv)
	if err != nil {
		return err
	}
	if err := preflightOutput(o); err != nil {
		return err
	}
	candidates, err := credentialCandidates(parsed, o, stdin)
	if err != nil {
		return err
	}
	defer wipeStrings(candidates)
	if parsed.CustomPassphrase && len(candidates) == 0 && o.nonInteractive {
		return fail(exitCredential, "no passphrase credential is available")
	}
	if parsed.CustomPassphrase && len(candidates) == 0 && !o.prompt && !isTerminal(stdin) {
		return fail(exitCredential, "no passphrase credential is available")
	}
	client, err := newAPIClient(settings.APIEndpoint)
	if err != nil {
		return err
	}
	retrieved, err := client.RetrieveMessage(context.Background(), parsed.MessageID)
	if err != nil {
		return fail(exitRetrieve, "message retrieval failed: %v", sanitizeAPIError(err))
	}
	result, err := decryptCandidates(retrieved.Envelope, parsed, candidates)
	if err != nil && !o.nonInteractive && (o.prompt || isTerminal(stdin)) {
		result, err = promptDecrypt(retrieved.Envelope, parsed)
	}
	if err != nil {
		return fail(exitDecrypt, "available credentials did not decrypt the message")
	}
	defer wipe(result.DeletionKey[:])
	defer wipeResult(&result)
	doc := parseDocument(result.Manifest.Message)
	if command == "read" {
		return outputRead(result, doc, o, stdout)
	}
	environment := os.Environ()
	for _, name := range []string{"WIPEME_PASSPHRASE", "WIPEME_PRIVATE_LINK", o.passEnv, o.linkEnv} {
		environment = removeEnv(environment, name)
	}
	for _, sel := range selectors {
		value, ok := selectText(doc, sel.block)
		if !ok {
			return fail(exitOutput, "selected message block does not contain text")
		}
		environment = removeEnv(environment, sel.name)
		environment = append(environment, sel.name+"="+value)
	}
	return runChild(child, stdin, stdout, stderr, environment)
}

func splitCommand(args []string) ([]string, []string) {
	for i, v := range args {
		if v == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}
func printAccessUsage(w io.Writer, c string) {
	if c == "read" {
		fmt.Fprintln(w, "Usage: wipeme read [options] <private-link>\n\nConsume, decrypt, and output a private message. Decrypted content may be written to stdout.")
	} else {
		fmt.Fprintln(w, "Usage: wipeme exec [options] <private-link> -- <command> [args...]\n\nConsume and inject decrypted content into a child process without invoking a shell.")
	}
	fmt.Fprint(w, "\nQuote private links containing #. Use --non-interactive for agents, containers, and CI/CD.\n\n")
}
func envTruthy(n string) bool {
	v := strings.ToLower(os.Getenv(n))
	return v == "1" || v == "true" || v == "yes"
}
func resolveLink(pos []string, o accessOptions) (string, error) {
	n := len(pos)
	if o.linkFile != "" {
		n++
	}
	if o.linkEnv != "" {
		n++
	}
	if n != 1 {
		return "", fail(exitUsage, "provide exactly one private link source")
	}
	if len(pos) == 1 {
		return pos[0], nil
	}
	if o.linkFile != "" {
		b, e := os.ReadFile(o.linkFile)
		if e != nil {
			return "", fail(exitLink, "read private link file: %v", e)
		}
		return trimLine(string(b)), nil
	}
	v, ok := os.LookupEnv(o.linkEnv)
	if !ok || v == "" {
		return "", fail(exitLink, "private link environment variable is unset or empty")
	}
	return v, nil
}
func trimLine(v string) string {
	if strings.HasSuffix(v, "\r\n") {
		return v[:len(v)-2]
	}
	if strings.HasSuffix(v, "\n") {
		return v[:len(v)-1]
	}
	return v
}
func credentialCandidates(link wipeme.ApplicationLink, o accessOptions, stdin io.Reader) ([]string, error) {
	var c []string
	if !link.CustomPassphrase {
		c = append(c, link.Secret)
	}
	if o.passFile != "" {
		b, e := os.ReadFile(o.passFile)
		if e != nil {
			return nil, fail(exitCredential, "read passphrase file: %v", e)
		}
		c = append(c, trimLine(string(b)))
	}
	if o.passStdin {
		b, e := io.ReadAll(stdin)
		if e != nil {
			return nil, fail(exitCredential, "read passphrase stdin: %v", e)
		}
		c = append(c, trimLine(string(b)))
	}
	if o.passEnv != "" {
		if v, ok := os.LookupEnv(o.passEnv); ok {
			c = append(c, v)
		}
	}
	if v, ok := os.LookupEnv("WIPEME_PASSPHRASE"); ok {
		c = append(c, v)
	}
	seen := map[string]bool{}
	out := c[:0]
	for _, v := range c {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}
func decryptCandidates(envelope []byte, link wipeme.ApplicationLink, c []string) (wipeme.DecryptResult, error) {
	for _, candidate := range c {
		id, secret := link.MessageID, candidate
		if !link.CustomPassphrase {
			var e error
			candidateLink := link
			candidateLink.Secret = candidate
			id, secret, e = candidateLink.EnvelopeCryptoParameters()
			if e != nil {
				continue
			}
		} else {
			var e error
			id, secret, e = wipeme.DeriveCustomCryptoParameters(candidate, link.MessageID)
			if e != nil {
				continue
			}
		}
		r, e := wipeme.Decrypt(bytes.NewReader(envelope), id, secret)
		if e == nil {
			return r, nil
		}
	}
	return wipeme.DecryptResult{}, errors.New("no candidate")
}
func promptDecrypt(envelope []byte, link wipeme.ApplicationLink) (wipeme.DecryptResult, error) {
	for i := 0; i < 3; i++ {
		candidate, e := readTTYPassphrase()
		if e != nil {
			return wipeme.DecryptResult{}, e
		}
		r, e := decryptCandidates(envelope, link, []string{candidate})
		candidate = ""
		if e == nil {
			return r, nil
		}
	}
	return wipeme.DecryptResult{}, errors.New("failed")
}
func readTTYPassphrase() (string, error) {
	tty, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return "", e
	}
	defer tty.Close()
	fmt.Fprint(tty, "Passphrase: ")
	b, e := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if e != nil {
		return "", e
	}
	value := string(b)
	wipe(b)
	return value, nil
}

type block struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}
type document struct {
	Blocks []block `json:"blocks"`
}

func parseDocument(s string) document {
	var d document
	if json.Unmarshal([]byte(s), &d) == nil && d.Blocks != nil {
		return d
	}
	return document{Blocks: []block{{Type: "paragraph", Data: map[string]any{"text": s}}}}
}
func textOf(b block) (string, bool) {
	switch b.Type {
	case "paragraph", "header", "quote", "code", "warning":
		for _, k := range []string{"text", "code", "message"} {
			if v, ok := b.Data[k].(string); ok {
				return stripHTML(v), true
			}
		}
	case "list":
		if items, ok := b.Data["items"].([]any); ok {
			var lines []string
			for _, x := range items {
				switch v := x.(type) {
				case string:
					lines = append(lines, stripHTML(v))
				case map[string]any:
					if c, ok := v["content"].(string); ok {
						lines = append(lines, stripHTML(c))
					}
				}
			}
			return strings.Join(lines, "\n"), true
		}
	}
	return "", false
}

var tags = regexp.MustCompile(`<[^>]*>`)

func stripHTML(v string) string { return html.UnescapeString(tags.ReplaceAllString(v, "")) }
func selectText(d document, n int) (string, bool) {
	if n >= 0 {
		if n >= len(d.Blocks) {
			return "", false
		}
		return textOf(d.Blocks[n])
	}
	for _, b := range d.Blocks {
		if v, ok := textOf(b); ok {
			return v, true
		}
	}
	return "", false
}

func preflightOutput(o accessOptions) error {
	if o.output != "" {
		if _, e := os.Lstat(o.output); !os.IsNotExist(e) {
			return fail(exitOutput, "output file already exists")
		}
		if _, e := os.Stat(filepath.Dir(o.output)); e != nil {
			return fail(exitOutput, "output directory is unavailable")
		}
	}
	if o.outputDir != "" {
		i, e := os.Stat(o.outputDir)
		if e != nil || !i.IsDir() {
			return fail(exitOutput, "attachment output directory is unavailable")
		}
	}
	return nil
}
func outputRead(r wipeme.DecryptResult, d document, o accessOptions, w io.Writer) error {
	var data []byte
	if o.json {
		data, _ = json.MarshalIndent(struct {
			Document    document                    `json:"document"`
			Attachments []wipeme.AttachmentMetadata `json:"attachments,omitempty"`
		}{d, r.Manifest.Attachments}, "", "  ")
		data = append(data, '\n')
	} else {
		v, ok := selectText(d, o.block)
		if !ok {
			return fail(exitOutput, "selected message block does not contain text")
		}
		data = []byte(v)
		if o.output == "" {
			data = append(data, '\n')
		}
	}
	if o.output != "" {
		if e := writePrivate(o.output, data); e != nil {
			return fail(exitOutput, "write output: %v", e)
		}
	} else {
		if _, e := w.Write(data); e != nil {
			return fail(exitOutput, "write output: %v", e)
		}
	}
	if o.outputDir != "" {
		for i, a := range r.Attachments {
			name := filepath.Base(a.Metadata.Name)
			if name == "." || name == "" || name == string(filepath.Separator) {
				name = fmt.Sprintf("attachment-%d", i+1)
			}
			if e := writePrivate(filepath.Join(o.outputDir, name), a.Data); e != nil {
				return fail(exitOutput, "write attachment: %v", e)
			}
		}
	}
	return nil
}
func writePrivate(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}

type selector struct {
	name  string
	block int
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateSelectors(values []string) ([]selector, error) {
	var out []selector
	for _, v := range values {
		p := strings.SplitN(v, "=", 2)
		if !envName.MatchString(p[0]) || strings.HasPrefix(p[0], "WIPEME_") {
			return nil, fail(exitUsage, "invalid or protected environment name")
		}
		s := selector{name: p[0], block: -1}
		if len(p) == 2 {
			if _, e := fmt.Sscanf(p[1], "block:%d", &s.block); e != nil || s.block < 0 {
				return nil, fail(exitUsage, "invalid block selector")
			}
		}
		out = append(out, s)
	}
	return out, nil
}
func removeEnv(env []string, name string) []string {
	if name == "" {
		return env
	}
	prefix := name + "="
	out := env[:0]
	for _, v := range env {
		if !strings.HasPrefix(v, prefix) {
			out = append(out, v)
		}
	}
	return out
}
func runChild(argv []string, stdin io.Reader, stdout, stderr io.Writer, env []string) error {
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin = stdin
	c.Stdout = stdout
	c.Stderr = stderr
	c.Env = env
	if e := c.Start(); e != nil {
		return fail(exitChild, "start child command: %v", e)
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	defer func() { close(done); signal.Stop(signals) }()
	go func() {
		for {
			select {
			case s := <-signals:
				if c.Process != nil {
					_ = c.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	if e := c.Wait(); e != nil {
		var x *exec.ExitError
		if errors.As(e, &x) {
			return &cliError{x.ExitCode(), fmt.Errorf("child exited with status %d", x.ExitCode())}
		}
		return fail(exitChild, "start child command: %v", e)
	}
	return nil
}
func wipeStrings(v []string) {
	for i := range v {
		v[i] = ""
	}
}
func wipeResult(r *wipeme.DecryptResult) {
	for i := range r.Attachments {
		wipe(r.Attachments[i].Data)
	}
	r.Manifest.Message = ""
}
func sanitizeAPIError(err error) error {
	if a, ok := wipeme.AsAPIError(err); ok {
		if a.StatusCode == 404 || a.StatusCode == 410 {
			return errors.New("message is unavailable or already consumed")
		}
		return fmt.Errorf("server returned status %d", a.StatusCode)
	}
	return errors.New("network or protocol error")
}
