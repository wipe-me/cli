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
	"strings"
	"testing"

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
	for _, expected := range []string{"wipeme [options] [file ...]", "wipeme delete [options] [link]", "Commands:", "-config", "-server-url", "-attach"} {
		if !strings.Contains(stderr.String(), expected) {
			t.Fatalf("help output %q does not contain %q", stderr.String(), expected)
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
	messageID, secret, err := wipeme.ParsePrivateLink(link.String())
	if err != nil {
		t.Fatal(err)
	}
	if messageID != uploadedID {
		t.Fatalf("uploaded ID %q differs from link ID %q", uploadedID, messageID)
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
	if receipt.MessageID != messageID || receipt.Secret != secret || receipt.CipherVersion != 1 {
		t.Fatalf("unexpected receipt %#v", receipt)
	}
	if info, err := os.Stat(receiptPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt permissions: info=%v err=%v", info, err)
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
