package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wipe-me/sdk/go/wipeme"
)

func encryptedFixture(t *testing.T, id, secret, message string) ([]byte, string) {
	t.Helper()
	var b bytes.Buffer
	if _, err := wipeme.Encrypt(&b, id, secret, message, nil); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b.Bytes())
	return b.Bytes(), hex.EncodeToString(sum[:])
}
func retrievalServer(t *testing.T, publicID string, envelope []byte, hash string, count *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*count++
		if r.Method != http.MethodGet || r.URL.Path != "/api/messages/"+publicID || r.URL.Fragment != "" {
			t.Errorf("unexpected retrieval %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("X-Wipe-Content-Hash", hash)
		w.Header().Set("X-Wipe-Cipher-Version", "1")
		w.Write(envelope)
	}))
}

func TestManualCandidateFallbackUsesOneRetrieval(t *testing.T) {
	clearConfigEnvironment(t)
	public := "aBc1dEf2"
	pass := "correct horse battery staple"
	id, secret, err := wipeme.DeriveCustomCryptoParameters(pass, public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, hash := encryptedFixture(t, id, secret, `{"blocks":[{"type":"image","data":{"file":{"name":"not-a-secret"}}},{"type":"paragraph","data":{"text":"manual value"}}]}`)
	count := 0
	server := retrievalServer(t, public, envelope, hash, &count)
	defer server.Close()
	file := filepath.Join(t.TempDir(), "wrong")
	os.WriteFile(file, []byte("wrong password\n"), 0600)
	t.Setenv("RIGHT_PASS", pass)
	var out, errs bytes.Buffer
	code := Run([]string{"read", "--api-url", server.URL, "--non-interactive", "--passphrase-file", file, "--passphrase-env", "RIGHT_PASS", "https://wipe.me/aBc1-dEf2"}, bytes.NewReader(nil), &out, &errs, "test")
	if code != 0 || out.String() != "manual value\n" || count != 1 {
		t.Fatalf("code=%d out=%q err=%q count=%d", code, out.String(), errs.String(), count)
	}
}

func TestInteractiveManualPassphraseFallsBackAfterWrongEnvironmentCandidate(t *testing.T) {
	public := "aBc1dEf2"
	passphrase := "correct horse battery staple"
	id, secret, err := wipeme.DeriveCustomCryptoParameters(passphrase, public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := encryptedFixture(t, id, secret, "interactive fallback value")
	link := wipeme.ApplicationLink{MessageID: public, CustomPassphrase: true}
	prompts := 0
	result, err := decryptWithPassphraseFallback(envelope, link, []string{"wrong environment value"}, true, func(attempt, maximum int) (string, error) {
		prompts++
		if attempt != 2 || maximum != defaultPassphraseAttempts {
			t.Fatalf("prompt attempt=%d maximum=%d", attempt, maximum)
		}
		return passphrase, nil
	})
	if err != nil || result.Manifest.Message != "interactive fallback value" || prompts != 1 {
		t.Fatalf("result=%#v prompts=%d err=%v", result.Manifest, prompts, err)
	}
	wipe(result.DeletionKey[:])
	wipeResult(&result)
}

func TestInteractiveManualPassphraseHasFiveTotalAttempts(t *testing.T) {
	public := "aBc1dEf2"
	passphrase := "correct horse battery staple"
	id, secret, err := wipeme.DeriveCustomCryptoParameters(passphrase, public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := encryptedFixture(t, id, secret, "never opened")
	link := wipeme.ApplicationLink{MessageID: public, CustomPassphrase: true}
	prompts := 0
	_, err = decryptWithPassphraseFallback(envelope, link, []string{"wrong environment value"}, true, func(attempt, maximum int) (string, error) {
		prompts++
		if attempt != prompts+1 || maximum != defaultPassphraseAttempts {
			t.Fatalf("prompt=%d attempt=%d maximum=%d", prompts, attempt, maximum)
		}
		return fmt.Sprintf("wrong prompted value %d", prompts), nil
	})
	if err == nil || prompts != defaultPassphraseAttempts-1 {
		t.Fatalf("prompts=%d err=%v", prompts, err)
	}
}

func TestAutomaticLinkFailureNeverPromptsForManualPassphrase(t *testing.T) {
	correct := wipeme.ApplicationLink{MessageID: "aB1cD2eF3", Secret: "123456789oab"}
	id, secret, err := correct.EnvelopeCryptoParameters()
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := encryptedFixture(t, id, secret, "automatic value")
	wrong := correct
	wrong.Secret = "222222222222"
	prompts := 0
	_, err = decryptWithPassphraseFallback(envelope, wrong, []string{wrong.Secret}, true, func(_, _ int) (string, error) {
		prompts++
		return correct.Secret, nil
	})
	if err == nil || prompts != 0 {
		t.Fatalf("automatic failure prompts=%d err=%v", prompts, err)
	}
}

func TestExecInjectsWithoutLeakingAndRemovesCredentialEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	app := wipeme.ApplicationLink{MessageID: "aB1cD2eF3", Secret: "123456789oab"}
	id, secret, err := app.EnvelopeCryptoParameters()
	if err != nil {
		t.Fatal(err)
	}
	envelope, hash := encryptedFixture(t, id, secret, `{"blocks":[{"type":"paragraph","data":{"text":"injected-value"}}]}`)
	count := 0
	server := retrievalServer(t, app.MessageID, envelope, hash, &count)
	defer server.Close()
	t.Setenv("WIPEME_PASSPHRASE", "must-be-removed")
	link, _ := wipeme.FormatApplicationPrivateLink("https://wipe.me", app.MessageID, app.Secret)
	var out, errs bytes.Buffer
	code := Run([]string{"exec", "--api-url", server.URL, "--set-env", "AGENT_SECRET", link, "--", "sh", "-c", `printf '%s:%s' "${WIPEME_PASSPHRASE-unset}" "$AGENT_SECRET"`}, bytes.NewReader(nil), &out, &errs, "test")
	if code != 0 || out.String() != "unset:injected-value" || strings.Contains(errs.String(), "injected-value") || count != 1 {
		t.Fatalf("code=%d out=%q err=%q count=%d", code, out.String(), errs.String(), count)
	}
}

func TestAutomaticFragmentFallsBackToFileCandidateWithoutAnotherRetrieval(t *testing.T) {
	clearConfigEnvironment(t)
	correct := wipeme.ApplicationLink{MessageID: "aB1cD2eF3", Secret: "123456789oab"}
	id, secret, err := correct.EnvelopeCryptoParameters()
	if err != nil {
		t.Fatal(err)
	}
	envelope, hash := encryptedFixture(t, id, secret, "fallback value")
	count := 0
	server := retrievalServer(t, correct.MessageID, envelope, hash, &count)
	defer server.Close()
	file := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(file, []byte(correct.Secret+"\n"), 0600)
	wrong, _ := wipeme.FormatApplicationPrivateLink("https://wipe.me", correct.MessageID, "222222222222")
	var out, errs bytes.Buffer
	code := Run([]string{"read", "--api-url", server.URL, "--non-interactive", "--passphrase-file", file, wrong}, bytes.NewReader(nil), &out, &errs, "test")
	if code != 0 || out.String() != "fallback value\n" || count != 1 {
		t.Fatalf("code=%d out=%q err=%q count=%d", code, out.String(), errs.String(), count)
	}
}

func TestOutputRefusesOverwriteBeforeRetrieval(t *testing.T) {
	clearConfigEnvironment(t)
	path := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(path, []byte("existing"), 0600)
	var out, errs bytes.Buffer
	code := Run([]string{"read", "--output", path, "https://wipe.me/aB1-cD2-eF3#123-456-789-oab"}, bytes.NewReader(nil), &out, &errs, "test")
	if code != exitOutput {
		t.Fatalf("code=%d err=%q", code, errs.String())
	}
	got, _ := os.ReadFile(path)
	if string(got) != "existing" {
		t.Fatal("existing output changed")
	}
}

func TestManualDeleteUsesPassphraseEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	public, pass := "aBc1dEf2", "correct horse battery staple"
	id, secret, err := wipeme.DeriveCustomCryptoParameters(pass, public)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := wipeme.DeriveDeletionKey(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodDelete || r.URL.Path != "/api/messages/"+public || r.Header.Get("X-Wipe-Deletion-Key") != wipeme.DeletionKeyHeader(expected) {
			t.Errorf("unexpected deletion request")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"deleted":true}`)
	}))
	defer server.Close()
	t.Setenv("DELETE_PASS", pass)
	var out, errs bytes.Buffer
	code := Run([]string{"delete", "--api-url", server.URL, "--non-interactive", "--passphrase-env", "DELETE_PASS", "https://wipe.me/aBc1-dEf2"}, bytes.NewReader(nil), &out, &errs, "test")
	if code != 0 || out.String() != "Deleted.\n" || calls != 1 {
		t.Fatalf("code=%d out=%q err=%q calls=%d", code, out.String(), errs.String(), calls)
	}
}

func TestGeneratedLinkFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	if err := writePrivate(path, []byte("private\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	if err := writePrivate(path, []byte("replace")); err == nil {
		t.Fatal("overwrote existing file")
	}
	_ = fmt.Sprintf("%s", path)
}
