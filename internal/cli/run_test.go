package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/wipe-me/cli/internal/media"
	"github.com/wipe-me/sdk/go/wipeme"
)

func TestBuildLink(t *testing.T) {
	got, err := buildLink("https://wipe.me", "1K7mQ2xR8VpC", "7YWHMfk9JCB7P4eG")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestVersionDoesNotContactServer(t *testing.T) {
	clearConfigEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--version"}, bytes.NewReader(nil), &stdout, &stderr, "1.2.3")
	if code != 0 || stdout.String() != "wipeme 1.2.3\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestHelpShowsMainCommandUsage(t *testing.T) {
	clearConfigEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--help"}, bytes.NewReader(nil), &stdout, &stderr, "test")
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{"wipeme [options] [file ...]", "wipeme read [options] <private-link>", "wipeme exec [options]", "wipeme delete [options] [link]", "Commands:", "-config", "-server-url", "-attach", "-generate-pass"} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("help output %q does not contain %q", stderr.String(), expected)
		}
	}
}

func TestAccessHelpReturnsSuccess(t *testing.T) {
	clearConfigEnvironment(t)
	for _, command := range []string{"read", "exec"} {
		var out, errs bytes.Buffer
		if code := Run([]string{command, "--help"}, bytes.NewReader(nil), &out, &errs, "test"); code != 0 || !strings.Contains(errs.String(), "Usage: wipeme "+command) {
			t.Fatalf("%s code=%d out=%q err=%q", command, code, out.String(), errs.String())
		}
	}
}

func TestInvalidFlagUsesStableUsageExitCode(t *testing.T) {
	clearConfigEnvironment(t)
	for _, args := range [][]string{{"--not-a-flag"}, {"read", "--not-a-flag"}, {"delete", "--not-a-flag"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, bytes.NewReader(nil), &stdout, &stderr, "test"); code != exitUsage {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
}

func TestHelpShowsDeleteCommandUsage(t *testing.T) {
	clearConfigEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"delete", "--help"}, bytes.NewReader(nil), &stdout, &stderr, "test")
	if code != 0 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, expected := range []string{"Usage: wipeme delete [options] [link]", "-config", "-api-url"} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("delete help output %q does not contain %q", stderr.String(), expected)
		}
	}
}

func TestNoInputFails(t *testing.T) {
	clearConfigEnvironment(t)
	var stdout, stderr bytes.Buffer
	code := Run(nil, bytes.NewReader(nil), &stdout, &stderr, "test")
	if code == 0 || !bytes.Contains(stderr.Bytes(), []byte("provide a message")) {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestProgressDisplayReplacesEncryptionWithUpload(t *testing.T) {
	var output bytes.Buffer
	display := &progressDisplay{writer: &output}
	display.update(wipeme.Progress{Phase: "encrypting", Percent: 10})
	display.update(wipeme.Progress{Phase: "encrypting", Percent: 100})
	display.update(wipeme.Progress{Phase: "uploading", Percent: 50})
	display.update(wipeme.Progress{Phase: "uploading", Percent: 100})
	display.finish()

	got := output.String()
	for _, want := range []string{
		"\rEncrypting... ▰▱▱▱▱▱▱▱▱▱▱▱  10%",
		"\rEncrypting... ▰▰▰▰▰▰▰▰▰▰▰▰ 100%",
		"\rUploading...  ▰▰▰▰▰▰▱▱▱▱▱▱  50%",
		"\rUploading...  ▰▰▰▰▰▰▰▰▰▰▰▰ 100%\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("progress output %q does not contain %q", got, want)
		}
	}
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("progress should finish with exactly one newline: %q", got)
	}
}

func TestProgressDisplayFinishesInterruptedLine(t *testing.T) {
	var output bytes.Buffer
	display := &progressDisplay{writer: &output}
	display.update(wipeme.Progress{Phase: "encrypting", Percent: 25})
	display.finish()
	display.finish()
	if got := output.String(); !strings.HasSuffix(got, " 25%\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("unexpected interrupted progress output %q", got)
	}
}

func TestInteractiveProgressIsDisabledForNonTerminalOutput(t *testing.T) {
	var stderr bytes.Buffer
	progress, finish := interactiveProgress(&stderr, false)
	if progress != nil {
		t.Fatal("expected progress to be disabled for non-terminal stderr")
	}
	finish()
	if stderr.Len() != 0 {
		t.Fatalf("unexpected progress output %q", stderr.String())
	}
}

func TestEndToEndUploadCanBeDecrypted(t *testing.T) {
	clearConfigEnvironment(t)
	var uploaded []byte
	var uploadedID string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.Header.Get("X-Wipe-Deletion-Key") == "" || request.Header.Get("X-Wipe-Cipher-Version") != "1" || request.Header.Get("X-Wipe-Client") != "cli" {
			t.Errorf("unexpected create request: %s %#v", request.Method, request.Header)
		}
		uploadedID = strings.TrimPrefix(request.URL.Path, "/api/messages/")
		var err error
		uploaded, err = io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read upload: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, uploadedID)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	receiptPath := filepath.Join(t.TempDir(), "creator.json")
	code := Run([]string{"--api-url", server.URL + "/api/messages", "--site-url", "https://wipe.me", "--receipt", receiptPath}, strings.NewReader("private message"), &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	link, err := url.Parse(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	application, err := wipeme.ParseApplicationPrivateLink(link.String())
	if err != nil {
		t.Fatal(err)
	}
	if application.MessageID != uploadedID {
		t.Fatalf("uploaded ID %q differs from link ID %q", uploadedID, application.MessageID)
	}
	messageID, secret, err := application.EnvelopeCryptoParameters()
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.Manifest.Message != "private message" {
		t.Fatalf("unexpected message %q", decrypted.Manifest.Message)
	}
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt creatorReceipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.MessageID != application.MessageID || receipt.Secret != application.Secret || receipt.CipherVersion != 1 {
		t.Fatalf("unexpected receipt %#v", receipt)
	}
	if info, err := os.Stat(receiptPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt permissions: info=%v err=%v", info, err)
	}
}

func TestCreateWithEnvironmentPassphraseUsesManualLink(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("WIPEME_PASSPHRASE", "123123123")
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploaded, _ = io.ReadAll(r.Body)
		id := strings.TrimPrefix(r.URL.Path, "/api/messages/")
		if len(id) != wipeme.CustomMessageIDLength {
			t.Errorf("unexpected public ID %q", id)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"created":true}`, id)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--api-url", server.URL, "--site-url", "https://wipe.me"}, strings.NewReader("manual message"), &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	link := strings.TrimSpace(stdout.String())
	if !regexp.MustCompile(`^https://wipe\.me/[1-9A-HJ-NP-Za-km-z]{4}-[1-9A-HJ-NP-Za-km-z]{4}$`).MatchString(link) {
		t.Fatalf("unexpected manual link %q", link)
	}
	application, err := wipeme.ParseApplicationPrivateLink(link)
	if err != nil {
		t.Fatal(err)
	}
	id, secret, err := wipeme.DeriveCustomCryptoParameters("123123123", application.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := wipeme.Decrypt(bytes.NewReader(uploaded), id, secret)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Manifest.Message != "manual message" {
		t.Fatalf("unexpected message %q", opened.Manifest.Message)
	}
}

func TestCreateReadAndOneTimeConsumption(t *testing.T) {
	clearConfigEnvironment(t)
	var envelope []byte
	var contentHash string
	consumed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			envelope, _ = io.ReadAll(r.Body)
			contentHash = r.Header.Get("X-Wipe-Content-Hash")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":%q,"created":true}`, strings.TrimPrefix(r.URL.Path, "/api/messages/"))
		case http.MethodGet:
			if consumed {
				http.Error(w, `{"error":"gone"}`, http.StatusNotFound)
				return
			}
			consumed = true
			w.Header().Set("X-Wipe-Content-Hash", contentHash)
			w.Header().Set("X-Wipe-Cipher-Version", "1")
			w.Write(envelope)
		}
	}))
	defer server.Close()
	var createOut, createErr bytes.Buffer
	if code := Run([]string{"--api-url", server.URL, "--site-url", "https://wipe.me"}, strings.NewReader("agent secret"), &createOut, &createErr, "test"); code != 0 {
		t.Fatalf("create code=%d err=%q", code, createErr.String())
	}
	link := strings.TrimSpace(createOut.String())
	if !regexp.MustCompile(`^https://wipe\.me/[1-9A-HJ-NP-Za-km-z]{3}(?:-[1-9A-HJ-NP-Za-km-z]{3}){2}#[1-9A-HJ-NP-Za-km-z]{3}(?:-[1-9A-HJ-NP-Za-km-z]{3}){3}$`).MatchString(link) {
		t.Fatalf("unexpected compact link %q", link)
	}
	var readOut, readErr bytes.Buffer
	if code := Run([]string{"read", "--api-url", server.URL, "--non-interactive", link}, bytes.NewReader(nil), &readOut, &readErr, "test"); code != 0 || readOut.String() != "agent secret\n" {
		t.Fatalf("read code=%d out=%q err=%q", code, readOut.String(), readErr.String())
	}
	readOut.Reset()
	readErr.Reset()
	if code := Run([]string{"read", "--api-url", server.URL, "--non-interactive", link}, bytes.NewReader(nil), &readOut, &readErr, "test"); code != exitRetrieve {
		t.Fatalf("second read code=%d err=%q", code, readErr.String())
	}
}

func TestEndToEndUploadSanitizesSupportedAttachment(t *testing.T) {
	clearConfigEnvironment(t)
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var err error
		uploaded, err = io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read upload: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()

	segment := func(marker byte, payload []byte) []byte {
		length := len(payload) + 2
		return append([]byte{0xff, marker, byte(length >> 8), byte(length)}, payload...)
	}
	pixelScan := []byte{1, 2, 3, 0xff, 0xd9}
	jpeg := append([]byte{0xff, 0xd8}, segment(0xe1, []byte("Exif GPS coordinates"))...)
	jpeg = append(jpeg, segment(0xda, []byte{1, 2})...)
	jpeg = append(jpeg, pixelScan...)
	attachmentPath := filepath.Join(t.TempDir(), "private-photo.jpg")
	if err := os.WriteFile(attachmentPath, jpeg, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"--api-url", server.URL, "--site-url", "https://wipe.me", attachmentPath},
		strings.NewReader("with attachment"),
		&stdout,
		&stderr,
		"test",
	)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	application, err := wipeme.ParseApplicationPrivateLink(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatal(err)
	}
	messageID, secret, err := application.EnvelopeCryptoParameters()
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted.Attachments) != 1 {
		t.Fatalf("unexpected attachments: %#v", decrypted.Attachments)
	}
	var document struct {
		Blocks []struct {
			Type string `json:"type"`
			Data struct {
				AttachmentIndex int `json:"attachmentIndex"`
			} `json:"data"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(decrypted.Manifest.Message), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Blocks) != 2 || document.Blocks[0].Type != "paragraph" || document.Blocks[1].Type != "attachment" || document.Blocks[1].Data.AttachmentIndex != 0 {
		t.Fatalf("attachment document was not linked correctly: %#v", document.Blocks)
	}
	data := decrypted.Attachments[0].Data
	if bytes.Contains(data, []byte("Exif")) || !bytes.HasSuffix(data, pixelScan) {
		t.Fatalf("attachment was not sanitized losslessly: %x", data)
	}
	if original, err := os.ReadFile(attachmentPath); err != nil || !bytes.Equal(original, jpeg) {
		t.Fatalf("original attachment changed: %x err=%v", original, err)
	}
}

func TestAttachmentOnlyDocumentContainsVisibleBlock(t *testing.T) {
	file := media.File{Name: "tmp.json", Type: "application/json", Kind: "file", Size: 3}
	message, err := addAttachmentBlocks("", []media.File{file})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Blocks []struct {
			Type string `json:"type"`
			Data struct {
				AttachmentIndex int `json:"attachmentIndex"`
			} `json:"data"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(message), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Blocks) != 1 || document.Blocks[0].Type != "attachment" || document.Blocks[0].Data.AttachmentIndex != 0 {
		t.Fatalf("unexpected attachment-only document: %s", message)
	}
}

func TestDeleteFromPrivateLink(t *testing.T) {
	clearConfigEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete || request.URL.Path != "/api/messages/1K7mQ2xR8VpC" || request.Header.Get("X-Wipe-Deletion-Key") == "" {
			t.Errorf("unexpected delete request: %s %s %#v", request.Method, request.URL.Path, request.Header)
		}
		_, _ = writer.Write([]byte(`{"deleted":true}`))
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	link := "https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG"
	code := Run([]string{"delete", "--api-url", server.URL}, strings.NewReader(link), &stdout, &stderr, "test")
	if code != 0 || stdout.String() != "Deleted.\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
