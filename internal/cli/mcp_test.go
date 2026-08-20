package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/sdk/go/wipeme"
)

const testAutomaticLink = "https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7"

func TestMCPHelpAndVersionDoNotStartServer(t *testing.T) {
	clearConfigEnvironment(t)
	for _, test := range []struct {
		args    []string
		wantOut string
		wantErr string
	}{
		{[]string{"mcp", "--help"}, "", "Usage: wipeme mcp [options]"},
		{[]string{"mcp", "--version"}, "wipeme 0.3.0-alpha.2-dev\n", ""},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(test.args, bytes.NewReader(nil), &stdout, &stderr, "0.3.0-alpha.2-dev"); code != 0 {
			t.Fatalf("args=%v code=%d stderr=%q", test.args, code, stderr.String())
		}
		if stdout.String() != test.wantOut || !strings.Contains(stderr.String(), test.wantErr) {
			t.Fatalf("args=%v stdout=%q stderr=%q", test.args, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"mcp", "--help"}, bytes.NewReader(nil), &stdout, &stderr, "test"); code != 0 || !strings.Contains(stderr.String(), "-access string") || !strings.Contains(stderr.String(), "default host") || !strings.Contains(stderr.String(), "-show-policy") {
		t.Fatalf("MCP help does not document access policy: code=%d stderr=%q", code, stderr.String())
	}
}

func TestMCPAccessPolicyDefaultsToHostAndSupportsRestrictedOverride(t *testing.T) {
	host, err := resolveMCPPolicy(nil, "")
	if err != nil || host.accessMode != mcpAccessHost {
		t.Fatalf("default policy=%#v err=%v", host, err)
	}

	restricted, err := resolveMCPPolicy(&mcpYAMLConfig{AccessMode: mcpAccessRestricted}, "")
	if err != nil || restricted.accessMode != mcpAccessRestricted {
		t.Fatalf("restricted policy=%#v err=%v", restricted, err)
	}

	overridden, err := resolveMCPPolicy(&mcpYAMLConfig{AccessMode: mcpAccessRestricted}, mcpAccessHost)
	if err != nil || overridden.accessMode != mcpAccessHost {
		t.Fatalf("overridden policy=%#v err=%v", overridden, err)
	}

	if _, err := resolveMCPPolicy(nil, "invalid"); err == nil || !strings.Contains(err.Error(), "host or restricted") {
		t.Fatalf("expected invalid access policy error, got %v", err)
	}
}

func TestMCPShowPolicyReportsEffectiveAccessAndExits(t *testing.T) {
	clearConfigEnvironment(t)
	invoke := func(args ...string) mcpPolicySummary {
		t.Helper()
		var stdout, stderr bytes.Buffer
		arguments := append([]string{"mcp"}, args...)
		if code := Run(arguments, bytes.NewReader(nil), &stdout, &stderr, "test"); code != 0 {
			t.Fatalf("args=%v code=%d stderr=%q", arguments, code, stderr.String())
		}
		var summary mcpPolicySummary
		if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
			t.Fatalf("args=%v output=%q err=%v", arguments, stdout.String(), err)
		}
		return summary
	}

	host := invoke("--show-policy")
	if host.AccessMode != mcpAccessHost || host.AccessSource != "default" || host.RestrictedAllowlists || !host.DirectProcessCommands {
		t.Fatalf("default summary=%#v", host)
	}

	root := t.TempDir()
	canonicalRoot := canonicalTestPath(t, root)
	configPath := writeTestConfig(t, fmt.Sprintf("mcp:\n  access_mode: restricted\n  allowed_read_roots: [%q]\n  allowed_write_roots: [%q]\n  allowed_source_env: [API_TOKEN]\n", root, root))
	restricted := invoke("--config", configPath, "--show-policy")
	if restricted.AccessMode != mcpAccessRestricted || restricted.AccessSource != "configuration" || !restricted.RestrictedAllowlists || restricted.DirectProcessCommands || len(restricted.AllowedWriteRoots) != 1 || restricted.AllowedWriteRoots[0] != canonicalRoot || len(restricted.AllowedSourceEnv) != 1 || restricted.AllowedSourceEnv[0] != "API_TOKEN" {
		t.Fatalf("restricted summary=%#v", restricted)
	}

	overridden := invoke("--config", configPath, "--access", "host", "--show-policy")
	if overridden.AccessMode != mcpAccessHost || overridden.AccessSource != "command_line" || overridden.RestrictedAllowlists || len(overridden.AllowedWriteRoots) != 0 {
		t.Fatalf("overridden summary=%#v", overridden)
	}
}

func TestMCPHostAccessUsesOSPermissionsWhileRestrictedUsesAllowlists(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "link")
	if err := os.WriteFile(path, []byte(testAutomaticLink+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	host := mcpPolicy{accessMode: mcpAccessHost}
	result, err := inspectPrivateLink(host, inspectPrivateLinkInput{LinkFile: path})
	if err != nil || !result.Valid {
		t.Fatalf("host result=%#v err=%v", result, err)
	}
	if !mcpEnvironmentAllowed(host, nil, "MCP_TEST_SECRET") {
		t.Fatal("host mode rejected a valid inherited environment name")
	}
	if _, err := validateMCPDestination(filepath.Join(root, "output"), host); err != nil {
		t.Fatalf("host mode rejected OS-writable destination: %v", err)
	}

	restricted := mcpPolicy{accessMode: mcpAccessRestricted}
	if _, err := inspectPrivateLink(restricted, inspectPrivateLinkInput{LinkFile: path}); err == nil || !strings.Contains(err.Error(), "path_outside_allowed_root") {
		t.Fatalf("restricted mode unexpectedly read outside an allowlist: %v", err)
	}
	if mcpEnvironmentAllowed(restricted, nil, "MCP_TEST_SECRET") {
		t.Fatal("restricted mode unexpectedly allowed an environment source")
	}
	if _, err := validateMCPDestination(filepath.Join(root, "output"), restricted); err == nil || !strings.Contains(err.Error(), "path_outside_allowed_root") {
		t.Fatalf("restricted mode unexpectedly allowed an output destination: %v", err)
	}
}

func TestMCPStdioContainsOnlyJSONRPCFraming(t *testing.T) {
	clearConfigEnvironment(t)
	recoveryDirectory := filepath.Join(t.TempDir(), "recovery")
	configPath := writeTestConfig(t, "mcp:\n  recovery_directory: "+recoveryDirectory+"\n")
	serverInput, clientOutput := io.Pipe()
	clientInput, serverOutput := io.Pipe()
	var wire, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		code := Run([]string{"mcp", "--config", configPath}, serverInput, io.MultiWriter(serverOutput, &wire), &stderr, "test")
		_ = serverOutput.Close()
		done <- code
	}()

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "stdio-test", Version: "test"}, nil)
	session, err := client.Connect(context.Background(), &mcpsdk.IOTransport{Reader: clientInput, Writer: clientOutput}, nil)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil || len(listed.Tools) != 15 {
		t.Fatalf("tools=%d err=%v", len(listed.Tools), err)
	}
	_ = session.Close()
	_ = clientOutput.Close()
	if code := <-done; code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("MCP wrote diagnostics during normal operation: %q", stderr.String())
	}
	for index, line := range bytes.Split(bytes.TrimSpace(wire.Bytes()), []byte{'\n'}) {
		if len(line) == 0 || !json.Valid(line) {
			t.Fatalf("stdout frame %d is not JSON: %q", index, line)
		}
	}
}

func TestMCPRegistersOnlyAgentSafeInspectionToolInitially(t *testing.T) {
	client, cleanup := connectMCPTestClient(t, mcpPolicy{})
	defer cleanup()

	listed, err := client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 15 {
		t.Fatalf("unexpected tools: %#v", listed.Tools)
	}
	expectedTools := map[string]bool{
		"inspect_private_link": false, "generate_secret": false, "generate_secret_into_process_env": false,
		"create_from_files": false, "create_from_env": false, "create_from_process_output": false,
		"consume_into_files": false, "retry_into_files": false, "consume_into_process_env": false,
		"retry_process_env": false, "consume_into_env_file": false, "retry_into_env_file": false,
		"generate_secret_into_env_file": false, "forget_recovery": false, "delete_message": false,
	}
	var tool *mcpsdk.Tool
	for _, candidate := range listed.Tools {
		if _, expected := expectedTools[candidate.Name]; !expected {
			t.Fatalf("unexpected MCP tool %q", candidate.Name)
		}
		expectedTools[candidate.Name] = true
		if candidate.Name == "inspect_private_link" {
			tool = candidate
		}
		for _, forbidden := range []string{"read", "plaintext", "consume_into_env", "create_message"} {
			if candidate.Name == forbidden {
				t.Fatalf("unsafe tool %q was registered", forbidden)
			}
		}
	}
	for name, found := range expectedTools {
		if !found {
			t.Fatalf("required MCP tool %q was not registered", name)
		}
	}
	if tool == nil {
		t.Fatal("inspect_private_link was not registered")
	}
	if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
		t.Fatalf("unexpected tool annotations: %#v", tool.Annotations)
	}
}

func TestMCPInspectPrivateLinkDoesNotEchoCapability(t *testing.T) {
	client, cleanup := connectMCPTestClient(t, mcpPolicy{})
	defer cleanup()

	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "inspect_private_link",
		Arguments: map[string]any{
			"private_link": testAutomaticLink,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %#v", result.Content)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, testAutomaticLink) || strings.Contains(text, "7YW-HMf-k9J-CB7") {
		t.Fatalf("MCP result echoed private capability: %s", text)
	}
	for _, expected := range []string{`"valid":true`, `"mode":"automatic"`, `"has_fragment_secret":true`, `"message_id":"1K7mQ2xR8"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("MCP result %s does not contain %s", text, expected)
		}
	}
}

func TestMCPInspectRejectsAmbiguousSourcesWithoutEchoingThem(t *testing.T) {
	client, cleanup := connectMCPTestClient(t, mcpPolicy{})
	defer cleanup()

	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "inspect_private_link",
		Arguments: map[string]any{
			"private_link": testAutomaticLink,
			"link_env":     "PRIVATE_LINK",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected tool error")
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "link_source_conflict") || strings.Contains(string(encoded), testAutomaticLink) {
		t.Fatalf("unsafe or unstable error result: %s", encoded)
	}
}

func TestMCPInspectReadsOnlyAllowlistedProtectedFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "link")
	if err := os.WriteFile(path, []byte(testAutomaticLink+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := mcpPolicy{allowedReadRoots: []string{canonicalTestPath(t, root)}, allowedLinkEnv: map[string]struct{}{}, allowedPassphraseEnv: map[string]struct{}{}, allowedSourceEnv: map[string]struct{}{}}
	result, err := inspectPrivateLink(policy, inspectPrivateLinkInput{LinkFile: path})
	if err != nil || !result.Valid || result.MessageID != "1K7mQ2xR8" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, err := inspectPrivateLink(policy, inspectPrivateLinkInput{LinkFile: filepath.Join(t.TempDir(), "link")}); err == nil || !strings.Contains(err.Error(), "path_outside_allowed_root") {
		t.Fatalf("expected path allowlist error, got %v", err)
	}
}

func TestMCPGenerateSecretReturnsLinkAndDecodableQRWithoutPlaintext(t *testing.T) {
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

	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, mcpPolicy{}, settings)
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "generate_secret",
		Arguments: map[string]any{
			"length":     24,
			"chars":      "base58",
			"include_qr": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %#v", result.Content)
	}
	var created mcpCreationResult
	structured, err := json.Marshal(result.StructuredContent)
	if err != nil || json.Unmarshal(structured, &created) != nil {
		t.Fatalf("decode structured result %s: %v", structured, err)
	}
	if created.Status != "created" || !created.QRIncluded || created.PrivateLink == "" {
		t.Fatalf("unexpected creation result: %#v", created)
	}
	application, err := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
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
	plaintext, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || len(plaintext) != 24 {
		t.Fatalf("unexpected generated plaintext envelope")
	}
	defer func() { plaintext = "" }()
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(plaintext)) {
		t.Fatal("generated plaintext leaked into MCP result")
	}

	var imageContent *mcpsdk.ImageContent
	for _, content := range result.Content {
		if image, ok := content.(*mcpsdk.ImageContent); ok {
			imageContent = image
		}
	}
	if imageContent == nil || imageContent.MIMEType != "image/png" || imageContent.Annotations == nil || len(imageContent.Annotations.Audience) != 1 || imageContent.Annotations.Audience[0] != mcpsdk.Role("user") {
		t.Fatalf("missing or invalid QR image content: %#v", imageContent)
	}
	decodedImage, err := png.Decode(bytes.NewReader(imageContent.Data))
	if err != nil {
		t.Fatal(err)
	}
	bitmap, err := gozxing.NewBinaryBitmapFromImage(decodedImage)
	if err != nil {
		t.Fatal(err)
	}
	decodedQR, err := qrcode.NewQRCodeReader().DecodeWithoutHints(bitmap)
	if err != nil {
		t.Fatalf("decode QR: %v", err)
	}
	if decodedQR.GetText() != created.PrivateLink {
		t.Fatalf("QR decoded %q, want private link", decodedQR.GetText())
	}
}

func TestMCPGeneratedLengthDistinguishesOmittedFromInvalidValues(t *testing.T) {
	if got, err := resolveMCPGeneratedLength(nil); err != nil || got != 32 {
		t.Fatalf("omitted length: got=%d err=%v", got, err)
	}
	for _, value := range []int{8, 32, 4096} {
		value := value
		if got, err := resolveMCPGeneratedLength(&value); err != nil || got != value {
			t.Fatalf("length %d: got=%d err=%v", value, got, err)
		}
	}
	for _, value := range []int{-1, 0, 7, 4097} {
		value := value
		if _, err := resolveMCPGeneratedLength(&value); err == nil || !strings.Contains(err.Error(), "invalid_arguments") {
			t.Fatalf("length %d: expected invalid_arguments, got %v", value, err)
		}
	}
}

func TestMCPGenerateSecretRejectsExplicitZeroBeforeUpload(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, cleanup := connectMCPTestClientWithConfig(t, mcpPolicy{}, config{
		APIEndpoint: server.URL,
		SiteURL:     "https://wipe.me",
		Expires:     24 * time.Hour,
	})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "generate_secret",
		Arguments: map[string]any{"length": 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if !result.IsError || !strings.Contains(string(encoded), "invalid_arguments") {
		t.Fatalf("expected invalid_arguments, got %s", encoded)
	}
	if requests != 0 {
		t.Fatalf("invalid length caused %d upload requests", requests)
	}
}

func TestMCPHostAccessCreatesFromInheritedEnvWithoutReturningSourceValue(t *testing.T) {
	const canary = "MCP_ENV_CANARY_secret-value"
	t.Setenv("MCP_TEST_API_TOKEN", canary)
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()

	policy := mcpPolicy{accessMode: mcpAccessHost, maxEnvironmentSources: 16}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "create_from_env",
		Arguments: map[string]any{"variables": []map[string]any{{"source": "MCP_TEST_API_TOKEN"}}},
	})
	if err != nil || result.IsError {
		t.Fatalf("err=%v result=%#v", err, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) {
		t.Fatal("environment plaintext leaked into MCP result")
	}
	var created mcpCreationResult
	structured, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(structured, &created); err != nil {
		t.Fatal(err)
	}
	application, _ := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
	messageID, secret, _ := application.EnvelopeCryptoParameters()
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || value != canary {
		t.Fatal("encrypted environment value did not round-trip")
	}
}

func TestMCPGenerateSecretSupportsAllowlistedManualPassphraseSource(t *testing.T) {
	const passphrase = "MCP manual passphrase with spaces"
	t.Setenv("MCP_TEST_MANUAL_PASS", passphrase)
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()
	policy := mcpPolicy{allowedPassphraseEnv: map[string]struct{}{"MCP_TEST_MANUAL_PASS": {}}}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "generate_secret",
		Arguments: map[string]any{
			"length":            20,
			"passphrase_source": map[string]any{"passphrase_env": "MCP_TEST_MANUAL_PASS"},
		},
	})
	if err != nil || result.IsError {
		t.Fatalf("err=%v result=%#v", err, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(passphrase)) {
		t.Fatal("manual passphrase leaked into MCP result")
	}
	var created mcpCreationResult
	structured, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(structured, &created); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(created.PrivateLink, "#") {
		t.Fatalf("manual private link unexpectedly contains a fragment: %q", created.PrivateLink)
	}
	application, err := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
	if err != nil || !application.CustomPassphrase {
		t.Fatalf("application=%#v err=%v", application, err)
	}
	messageID, secret, err := wipeme.DeriveCustomCryptoParameters(passphrase, application.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	generated, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || len(generated) != 20 {
		t.Fatal("generated manual-mode secret did not round-trip")
	}
}

func TestMCPCreateFromFilesEncryptsMessageAndAttachments(t *testing.T) {
	root := t.TempDir()
	messagePath := filepath.Join(root, "message.txt")
	attachmentPath := filepath.Join(root, "attachment.txt")
	if err := os.WriteFile(messagePath, []byte("protected file message"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attachmentPath, []byte("protected attachment"), 0o600); err != nil {
		t.Fatal(err)
	}
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()
	policy := mcpPolicy{allowedReadRoots: []string{canonicalTestPath(t, root)}}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "create_from_files",
		Arguments: map[string]any{
			"message_file":     messagePath,
			"attachment_paths": []string{attachmentPath},
		},
	})
	if err != nil || result.IsError {
		t.Fatalf("err=%v result=%#v", err, result)
	}
	var created mcpCreationResult
	structured, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(structured, &created); err != nil || created.AttachmentCount != 1 {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	application, _ := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
	messageID, secret, _ := application.EnvelopeCryptoParameters()
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	message, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || message != "protected file message" || len(decrypted.Attachments) != 1 || string(decrypted.Attachments[0].Data) != "protected attachment" {
		t.Fatal("file inputs did not round-trip through the encrypted envelope")
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte("protected file message")) || bytes.Contains(wire, []byte("protected attachment")) {
		t.Fatal("file plaintext leaked into MCP result")
	}
}

func TestMCPCreateFromApprovedProducerDoesNotReturnProcessOutput(t *testing.T) {
	const canary = "MCP_PROCESS_CANARY_secret-output"
	t.Setenv("MCP_HELPER_MODE", "success")
	t.Setenv("MCP_HELPER_SECRET", canary)
	profile, err := resolveMCPProcessProfile("test-producer", mcpProcessProfile{
		Role:              "producer",
		Executable:        os.Args[0],
		FixedArgs:         []string{"-test.run=^TestMCPProducerHelperProcess$"},
		InheritEnv:        []string{"MCP_HELPER_MODE", "MCP_HELPER_SECRET"},
		AcceptedExitCodes: []int{0},
		MaxStdoutBytes:    4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()

	policy := mcpPolicy{processProfiles: map[string]mcpResolvedProcessProfile{"test-producer": profile}}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "create_from_process_output",
		Arguments: map[string]any{
			"profile": "test-producer",
			"output":  map[string]any{"mode": "text"},
		},
	})
	if err != nil || result.IsError {
		t.Fatalf("err=%v result=%#v", err, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) {
		t.Fatal("producer stdout leaked into MCP result")
	}
	var created mcpCreationResult
	structured, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(structured, &created); err != nil {
		t.Fatal(err)
	}
	application, _ := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
	messageID, secret, _ := application.EnvelopeCryptoParameters()
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || value != canary {
		t.Fatal("encrypted producer output did not round-trip")
	}
}

func TestMCPHostModeRunsDirectProducerWithoutProfile(t *testing.T) {
	const canary = "MCP_HOST_PROCESS_CANARY_secret-output"
	t.Setenv("MCP_HELPER_MODE", "success")
	t.Setenv("MCP_HELPER_SECRET", canary)
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()

	policy := mcpPolicy{accessMode: mcpAccessHost}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "create_from_process_output",
		Arguments: map[string]any{
			"command":   os.Args[0],
			"arguments": []string{"-test.run=^TestMCPProducerHelperProcess$"},
			"output":    map[string]any{"mode": "text"},
		},
	})
	if err != nil || result.IsError {
		t.Fatalf("err=%v result=%#v", err, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) {
		t.Fatal("host producer stdout leaked into MCP result")
	}
	var created mcpCreationResult
	structured, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(structured, &created); err != nil {
		t.Fatal(err)
	}
	application, _ := wipeme.ParseApplicationPrivateLink(created.PrivateLink)
	messageID, secret, _ := application.EnvelopeCryptoParameters()
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || value != canary {
		t.Fatal("host command output did not round-trip through encryption")
	}
}

func TestMCPHostModeAcceptsLegacyProfileFieldAsCommand(t *testing.T) {
	resolved, storedProfile, storedCommand, err := resolveMCPProcessCall(mcpPolicy{accessMode: mcpAccessHost}, "echo", "", "consumer", nil)
	if err != nil || resolved.executable == "" || storedProfile != "" || storedCommand != "echo" {
		t.Fatalf("resolved=%#v profile=%q command=%q err=%v", resolved, storedProfile, storedCommand, err)
	}
}

func TestMCPProducerFailureDoesNotReturnProcessOutput(t *testing.T) {
	const canary = "MCP_PROCESS_FAILURE_CANARY"
	t.Setenv("MCP_HELPER_MODE", "fail")
	t.Setenv("MCP_HELPER_SECRET", canary)
	profile, err := resolveMCPProcessProfile("test-producer", mcpProcessProfile{
		Role:           "producer",
		Executable:     os.Args[0],
		FixedArgs:      []string{"-test.run=^TestMCPProducerHelperProcess$"},
		InheritEnv:     []string{"MCP_HELPER_MODE", "MCP_HELPER_SECRET"},
		MaxStdoutBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := mcpPolicy{processProfiles: map[string]mcpResolvedProcessProfile{"test-producer": profile}}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "create_from_process_output",
		Arguments: map[string]any{"profile": "test-producer", "output": map[string]any{"mode": "text"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(result)
	if !result.IsError || !bytes.Contains(wire, []byte("producer_failed")) || bytes.Contains(wire, []byte(canary)) {
		t.Fatalf("unsafe producer failure: %s", wire)
	}
}

func TestMCPDeleteMessageUsesCapabilityWithoutEchoingIt(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodDelete || request.Header.Get("X-Wipe-Deletion-Key") == "" {
			t.Errorf("unexpected deletion request: %s %#v", request.Method, request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"deleted":true}`))
	}))
	defer server.Close()

	client, cleanup := connectMCPTestClientWithConfig(t, mcpPolicy{}, config{APIEndpoint: server.URL})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "delete_message",
		Arguments: map[string]any{"private_link": testAutomaticLink},
	})
	if err != nil || result.IsError || requests != 1 {
		t.Fatalf("err=%v requests=%d result=%#v", err, requests, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(testAutomaticLink)) || bytes.Contains(wire, []byte("7YW-HMf-k9J-CB7")) || !bytes.Contains(wire, []byte(`"status":"deleted"`)) {
		t.Fatalf("unsafe deletion result: %s", wire)
	}
}

func TestMCPConsumeIntoFilesWritesPrivateOutputsWithoutReturningPlaintext(t *testing.T) {
	const canary = "MCP_CONSUME_CANARY_private-message"
	link, envelope, contentHash := encryptedMCPTestMessage(t, canary, []wipeme.AttachmentInput{
		{Reader: strings.NewReader("first attachment"), Name: "private-note.md", Type: "text/plain", Kind: "text", Size: int64(len("first attachment"))},
		{Reader: strings.NewReader("second attachment"), Name: "private-note.md", Type: "text/plain", Kind: "text", Size: int64(len("second attachment"))},
	})
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets++
		writer.Header().Set("X-Wipe-Content-Hash", contentHash)
		writer.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = writer.Write(envelope)
	}))
	defer server.Close()

	root := t.TempDir()
	destination := filepath.Join(root, "consumed")
	policy := mcpPolicy{allowedWriteRoots: []string{canonicalTestPath(t, root)}, recoveryDirectory: filepath.Join(t.TempDir(), "recovery"), recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "consume_into_files",
		Arguments: map[string]any{
			"private_link":          link,
			"destination_directory": destination,
			"message_filename":      "private-note.md",
		},
	})
	if err != nil || result.IsError || gets != 1 {
		t.Fatalf("err=%v gets=%d result=%#v", err, gets, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) || bytes.Contains(wire, []byte("first attachment")) {
		t.Fatalf("plaintext leaked into consume result: %s", wire)
	}
	var output mcpFileConsumptionOutput
	structured, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(structured, &output); err != nil || output.MessageFilename != "private-note.md" {
		t.Fatalf("output=%#v err=%v", output, err)
	}
	message, err := os.ReadFile(filepath.Join(destination, "private-note.md"))
	if err != nil || string(message) != canary {
		t.Fatalf("message=%q err=%v", message, err)
	}
	first, err := os.ReadFile(filepath.Join(destination, "001-private-note.md"))
	if err != nil || string(first) != "first attachment" {
		t.Fatalf("first attachment=%q err=%v", first, err)
	}
	second, err := os.ReadFile(filepath.Join(destination, "002-private-note.md"))
	if err != nil || string(second) != "second attachment" {
		t.Fatalf("second attachment=%q err=%v", second, err)
	}
	for _, path := range []string{destination, filepath.Join(destination, "private-note.md"), filepath.Join(destination, "001-private-note.md"), filepath.Join(destination, "002-private-note.md")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s permissions=%o want=%o", path, info.Mode().Perm(), want)
		}
	}
}

func TestMCPMessageFilenameValidationRejectsPathsAndControls(t *testing.T) {
	for _, value := range []string{"../secret", "sub/secret", `sub\secret`, ".", "..", "line\nbreak"} {
		if _, err := resolveMCPMessageFilename(value, "text"); err == nil || !strings.Contains(err.Error(), "safe basename") {
			t.Fatalf("unsafe message filename %q accepted: %v", value, err)
		}
	}
	for _, test := range []struct {
		value  string
		format string
		want   string
	}{
		{"", "text", "message.txt"},
		{"", "editorjs_json", "message.json"},
		{"секрет.txt", "text", "секрет.txt"},
	} {
		got, err := resolveMCPMessageFilename(test.value, test.format)
		if err != nil || got != test.want {
			t.Fatalf("value=%q format=%q got=%q want=%q err=%v", test.value, test.format, got, test.want, err)
		}
	}
	writeMessage := false
	if _, err := resolveMCPFileOutputOptions("/unused", "text", "secret.txt", nil, &writeMessage, nil, mcpPolicy{}); err == nil || !strings.Contains(err.Error(), "requires write_message") {
		t.Fatalf("message_filename without message output accepted: %v", err)
	}
}

func TestMCPRetryIntoFilesDoesNotRetrieveAgain(t *testing.T) {
	const canary = "MCP_RETRY_CANARY_private-message"
	link, envelope, contentHash := encryptedMCPTestMessage(t, canary, nil)
	root := t.TempDir()
	destination := filepath.Join(root, "consumed")
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets++
		if gets == 1 {
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Errorf("create destination race: %v", err)
			}
		}
		writer.Header().Set("X-Wipe-Content-Hash", contentHash)
		writer.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = writer.Write(envelope)
	}))
	defer server.Close()

	recoveryDir := filepath.Join(t.TempDir(), "recovery")
	policy := mcpPolicy{allowedWriteRoots: []string{canonicalTestPath(t, root)}, recoveryDirectory: recoveryDir, recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	first, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "consume_into_files",
		Arguments: map[string]any{"private_link": link, "destination_directory": destination},
	})
	if err != nil || first.IsError {
		t.Fatalf("err=%v result=%#v", err, first)
	}
	var pending mcpFileConsumptionOutput
	structured, _ := json.Marshal(first.StructuredContent)
	if err := json.Unmarshal(structured, &pending); err != nil || pending.Status != "output_failed" || pending.RecoveryHandle == "" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	retried, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "retry_into_files",
		Arguments: map[string]any{
			"recovery_handle":       pending.RecoveryHandle,
			"destination_directory": destination,
			"message_filename":      "recovered-secret.txt",
		},
	})
	if err != nil || retried.IsError || gets != 1 {
		t.Fatalf("err=%v gets=%d result=%#v", err, gets, retried)
	}
	message, err := os.ReadFile(filepath.Join(destination, "recovered-secret.txt"))
	if err != nil || string(message) != canary {
		t.Fatalf("message=%q err=%v", message, err)
	}
	entries, err := os.ReadDir(recoveryDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("successful retry left recovery files: %#v", entries)
	}
}

func TestMCPEnvironmentFileEncodersUseExplicitNativeFormats(t *testing.T) {
	mappings := []mcpEnvironmentMapping{{Name: "PRIVATE_KEY", Block: 0}}
	values := map[string]string{"PRIVATE_KEY": "line 1\nline '$2' \\\""}
	tests := []struct {
		format string
		want   string
	}{
		{mcpEnvFormatDotenv, "# wipeme-format: dotenv\nPRIVATE_KEY=\"line 1\\nline '\\$2' \\\\\\\"\"\n"},
		{mcpEnvFormatShell, "# wipeme-format: shell\nexport PRIVATE_KEY='line 1\nline '\"'\"'$2'\"'\"' \\\"'\n"},
		{mcpEnvFormatSystemd, "# wipeme-format: systemd\nPRIVATE_KEY=\"line 1\nline '\\$2' \\\\\\\"\"\n"},
	}
	for _, test := range tests {
		encoded, err := encodeMCPEnvFile(test.format, mappings, values)
		if err != nil || string(encoded) != test.want {
			t.Fatalf("format=%s encoded=%q want=%q err=%v", test.format, encoded, test.want, err)
		}
	}
	if _, err := encodeMCPEnvFile(mcpEnvFormatDocker, mappings, values); err == nil || !strings.Contains(err.Error(), "cannot contain newlines") {
		t.Fatalf("Docker encoder accepted a multiline value: %v", err)
	}
	values["PRIVATE_KEY"] = "single-line=$literal#value"
	encoded, err := encodeMCPEnvFile(mcpEnvFormatDocker, mappings, values)
	if err != nil || string(encoded) != "# wipeme-format: docker\nPRIVATE_KEY=single-line=$literal#value\n" {
		t.Fatalf("Docker encoded=%q err=%v", encoded, err)
	}
}

func TestMCPEnvironmentFileOverwritePreservesUnrelatedContent(t *testing.T) {
	mappings := []mcpEnvironmentMapping{{Name: "TARGET", Block: 0}}
	values := map[string]string{"TARGET": "new secret"}
	tests := []struct {
		format   string
		existing string
		want     string
	}{
		{
			mcpEnvFormatDotenv,
			"# wipeme-format: dotenv\n# owned by the application\nKEEP=\"same\"\nTARGET=\"old\"\n# trailing comment\n",
			"# wipeme-format: dotenv\n# owned by the application\nKEEP=\"same\"\n# trailing comment\nTARGET=\"new secret\"\n",
		},
		{
			mcpEnvFormatDocker,
			"# existing Docker file\nKEEP=same\nTARGET=old\nTARGET\n# trailing comment\n",
			"# existing Docker file\nKEEP=same\n# trailing comment\nTARGET=new secret\n",
		},
		{
			mcpEnvFormatShell,
			"#!/bin/sh\n# sourced by the application\nexport KEEP='same'\nexport TARGET='old\nvalue'\n# trailing comment\n",
			"#!/bin/sh\n# sourced by the application\nexport KEEP='same'\n# trailing comment\nexport TARGET='new secret'\n",
		},
		{
			mcpEnvFormatSystemd,
			"; managed by the application\nKEEP=\"same\"\nTARGET=\"old\nvalue\"\n# trailing comment\n",
			"; managed by the application\nKEEP=\"same\"\n# trailing comment\nTARGET=\"new secret\"\n",
		},
	}
	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "application.env")
			if err := os.WriteFile(destination, []byte(test.existing), 0o644); err != nil {
				t.Fatal(err)
			}
			options := mcpEnvFileOptions{destination: destination, mappings: mappings, format: test.format, overwrite: true}
			if err := materializeMCPEnvFile(options, values); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(destination)
			info, statErr := os.Stat(destination)
			if err != nil || statErr != nil || string(data) != test.want || info.Mode().Perm() != 0o600 {
				t.Fatalf("data=%q want=%q mode=%v readErr=%v statErr=%v", data, test.want, info.Mode().Perm(), err, statErr)
			}
		})
	}
}

func TestMCPEnvironmentFileOverwriteRefusesMalformedTargetWithoutChangingFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "application.env")
	existing := []byte("# application settings\nTARGET=\"unterminated\nKEEP=untouched\n")
	if err := os.WriteFile(destination, existing, 0o600); err != nil {
		t.Fatal(err)
	}
	options := mcpEnvFileOptions{
		destination: destination, mappings: []mcpEnvironmentMapping{{Name: "TARGET", Block: 0}},
		format: mcpEnvFormatDotenv, overwrite: true,
	}
	if err := materializeMCPEnvFile(options, map[string]string{"TARGET": "replacement"}); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed assignment was accepted: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(data, existing) {
		t.Fatalf("existing file changed: data=%q err=%v", data, err)
	}
}

func TestMCPConsumeIntoExistingEnvironmentFilePreservesUnrelatedContent(t *testing.T) {
	const canary = "MCP_ENV_FILE_PRESERVE_CANARY"
	document, err := encodeTextBlocks([]string{canary})
	if err != nil {
		t.Fatal(err)
	}
	link, envelope, contentHash := encryptedMCPTestMessage(t, document, nil)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Wipe-Content-Hash", contentHash)
		writer.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = writer.Write(envelope)
	}))
	defer server.Close()

	root := t.TempDir()
	destination := filepath.Join(root, "application.env")
	existing := "# application-owned file\nKEEP=untouched\nPRIVATE_KEY=old-value\n# trailing comment\n"
	if err := os.WriteFile(destination, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := mcpPolicy{
		allowedWriteRoots: []string{canonicalTestPath(t, root)}, recoveryDirectory: filepath.Join(t.TempDir(), "recovery"),
		recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5,
	}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "consume_into_env_file",
		Arguments: map[string]any{
			"private_link": link, "destination_file": destination, "overwrite": true,
			"environment": []map[string]any{{"name": "PRIVATE_KEY", "block": 0}},
		},
	})
	if err != nil || result.IsError {
		t.Fatalf("err=%v result=%#v", err, result)
	}
	want := "# application-owned file\nKEEP=untouched\n# trailing comment\nPRIVATE_KEY=\"" + canary + "\"\n"
	data, readErr := os.ReadFile(destination)
	if readErr != nil || string(data) != want {
		t.Fatalf("environment file=%q want=%q err=%v", data, want, readErr)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) {
		t.Fatalf("environment plaintext leaked into MCP result: %s", wire)
	}
}

func TestMCPEnvironmentFileFormatAutodetection(t *testing.T) {
	root := t.TempDir()
	policy := mcpPolicy{allowedWriteRoots: []string{canonicalTestPath(t, root)}}
	selectors := []mcpEnvironmentSelector{{Name: "PRIVATE_KEY"}}
	for _, format := range []string{mcpEnvFormatDotenv, mcpEnvFormatDocker, mcpEnvFormatShell, mcpEnvFormatSystemd} {
		path := filepath.Join(root, "existing-"+format+".env")
		data := []byte(mcpEnvFormatMarker + format + "\nPRIVATE_KEY=existing\n")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		options, err := resolveMCPEnvFileOptions(path, selectors, "", true, policy, false)
		if err != nil || options.format != format {
			t.Fatalf("format=%q detected=%q err=%v", format, options.format, err)
		}
	}
	for _, test := range []struct {
		name    string
		content string
		want    string
	}{
		{"legacy.sh", "PRIVATE_KEY=existing\n", mcpEnvFormatShell},
		{"legacy.docker.env", "PRIVATE_KEY=existing\n", mcpEnvFormatDocker},
		{"legacy.systemd.env", "PRIVATE_KEY=existing\n", mcpEnvFormatSystemd},
		{"legacy.env", "PRIVATE_KEY=existing\n", mcpEnvFormatDotenv},
		{"content-over-name.systemd", "PRIVATE_KEY=existing\nexport API_TOKEN='token'\n", mcpEnvFormatShell},
		{"content-over-name.sh", "PRIVATE_KEY=existing\n; managed by systemd\n", mcpEnvFormatSystemd},
		{"shebang.env", "#!/usr/bin/env bash\nPRIVATE_KEY=existing\n", mcpEnvFormatShell},
		{"dotenv-escapes", "PRIVATE_KEY=\"line\\nvalue\"\n", mcpEnvFormatDotenv},
		{"systemd-escapes", "PRIVATE_KEY=\"literal\\`tick\"\n", mcpEnvFormatSystemd},
		{"neutral", "PRIVATE_KEY=existing\n", mcpEnvFormatDotenv},
	} {
		path := filepath.Join(root, test.name)
		if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
			t.Fatal(err)
		}
		options, err := resolveMCPEnvFileOptions(path, selectors, "", true, policy, false)
		if err != nil || options.format != test.want {
			t.Fatalf("name=%q detected=%q want=%q err=%v", test.name, options.format, test.want, err)
		}
	}
}

func TestMCPEnvironmentFileOverwriteIsExplicitAndRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "application.env")
	if err := os.WriteFile(destination, []byte("OLD=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := mcpPolicy{allowedWriteRoots: []string{canonicalTestPath(t, root)}}
	if _, err := validateMCPEnvFileDestination(destination, false, policy); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("no-overwrite validation accepted an existing file: %v", err)
	}
	path, err := validateMCPEnvFileDestination(destination, true, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicPrivateFile(path, []byte("NEW=value\n"), true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	info, statErr := os.Stat(destination)
	mode := os.FileMode(0)
	if info != nil {
		mode = info.Mode().Perm()
	}
	if err != nil || statErr != nil || string(data) != "NEW=value\n" || mode != 0o600 {
		t.Fatalf("data=%q mode=%v readErr=%v statErr=%v", data, mode, err, statErr)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := validateMCPEnvFileDestination(destination, true, policy); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("overwrite validation accepted a symlink: %v", err)
	}
}

func TestMCPConsumeIntoEnvFileRetriesWithoutAnotherRetrieval(t *testing.T) {
	const firstCanary = "MCP_ENV_FILE_CANARY_first"
	const secondCanary = "MCP_ENV_FILE_CANARY_second"
	document, err := encodeTextBlocks([]string{firstCanary, secondCanary})
	if err != nil {
		t.Fatal(err)
	}
	link, envelope, contentHash := encryptedMCPTestMessage(t, document, nil)
	root := t.TempDir()
	destination := filepath.Join(root, "application.env")
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets++
		if gets == 1 {
			if err := os.WriteFile(destination, []byte("race"), 0o600); err != nil {
				t.Errorf("create destination race: %v", err)
			}
		}
		writer.Header().Set("X-Wipe-Content-Hash", contentHash)
		writer.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = writer.Write(envelope)
	}))
	defer server.Close()

	recoveryDir := filepath.Join(t.TempDir(), "recovery")
	policy := mcpPolicy{allowedWriteRoots: []string{canonicalTestPath(t, root)}, recoveryDirectory: recoveryDir, recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	first, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "consume_into_env_file",
		Arguments: map[string]any{
			"private_link": link, "destination_file": destination,
			"environment": []map[string]any{{"name": "PRIVATE_KEY", "block": 0}, {"name": "API_TOKEN", "block": 1}},
		},
	})
	if err != nil || first.IsError || gets != 1 {
		t.Fatalf("err=%v gets=%d result=%#v", err, gets, first)
	}
	var pending mcpEnvFileOutput
	structured, _ := json.Marshal(first.StructuredContent)
	if err := json.Unmarshal(structured, &pending); err != nil || pending.Status != "output_failed" || pending.RecoveryHandle == "" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	wire, _ := json.Marshal(first)
	if bytes.Contains(wire, []byte(firstCanary)) || bytes.Contains(wire, []byte(secondCanary)) {
		t.Fatalf("environment plaintext leaked into pending result: %s", wire)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	retried, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "retry_into_env_file",
		Arguments: map[string]any{"recovery_handle": pending.RecoveryHandle},
	})
	if err != nil || retried.IsError || gets != 1 {
		t.Fatalf("err=%v gets=%d result=%#v", err, gets, retried)
	}
	data, err := os.ReadFile(destination)
	want := "# wipeme-format: dotenv\nPRIVATE_KEY=\"" + firstCanary + "\"\nAPI_TOKEN=\"" + secondCanary + "\"\n"
	if err != nil || string(data) != want {
		t.Fatalf("environment file=%q want=%q err=%v", data, want, err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("environment file permissions=%v err=%v", info.Mode().Perm(), err)
	}
	wire, _ = json.Marshal(retried)
	if bytes.Contains(wire, []byte(firstCanary)) || bytes.Contains(wire, []byte(secondCanary)) {
		t.Fatalf("environment plaintext leaked into retry result: %s", wire)
	}
}

func TestMCPGenerateSecretIntoEnvFileRetriesSameSecretAndThenReleasesLink(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "generated.env")
	puts := 0
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut {
			t.Errorf("unexpected method %s", request.Method)
		}
		puts++
		uploaded, _ = io.ReadAll(request.Body)
		if puts == 1 {
			if err := os.WriteFile(destination, []byte("race"), 0o600); err != nil {
				t.Errorf("create destination race: %v", err)
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()

	recoveryDir := filepath.Join(t.TempDir(), "recovery")
	policy := mcpPolicy{allowedWriteRoots: []string{canonicalTestPath(t, root)}, recoveryDirectory: recoveryDir, recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	first, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "generate_secret_into_env_file",
		Arguments: map[string]any{
			"destination_file": destination, "format": "docker", "length": 24, "chars": "base58",
			"environment": []map[string]any{{"name": "DATABASE_PASSWORD", "block": 0}},
		},
	})
	if err != nil || first.IsError || puts != 1 {
		t.Fatalf("err=%v puts=%d result=%#v", err, puts, first)
	}
	var pending mcpEnvFileOutput
	structured, _ := json.Marshal(first.StructuredContent)
	if err := json.Unmarshal(structured, &pending); err != nil || pending.Status != "output_failed" || pending.RecoveryHandle == "" || pending.PrivateLink != "" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	retried, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "retry_into_env_file",
		Arguments: map[string]any{"recovery_handle": pending.RecoveryHandle, "include_qr": true},
	})
	if err != nil || retried.IsError || puts != 1 {
		t.Fatalf("err=%v puts=%d result=%#v", err, puts, retried)
	}
	var completed mcpEnvFileOutput
	structured, _ = json.Marshal(retried.StructuredContent)
	if err := json.Unmarshal(structured, &completed); err != nil || completed.Status != "written" || completed.PrivateLink == "" || !completed.QRIncluded {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || !bytes.HasPrefix(data, []byte("# wipeme-format: docker\nDATABASE_PASSWORD=")) {
		t.Fatalf("generated environment file=%q err=%v", data, err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("generated environment file lines=%q", lines)
	}
	generated := strings.TrimPrefix(string(lines[1]), "DATABASE_PASSWORD=")
	if len(generated) != 24 {
		t.Fatalf("generated secret length=%d", len(generated))
	}
	application, err := wipeme.ParseApplicationPrivateLink(completed.PrivateLink)
	if err != nil {
		t.Fatal(err)
	}
	messageID, secret, _ := application.EnvelopeCryptoParameters()
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	decryptedSecret, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || decryptedSecret != generated {
		t.Fatal("environment retry did not reuse the originally uploaded generated secret")
	}
	wire, _ := json.Marshal(retried)
	if bytes.Contains(wire, []byte(generated)) {
		t.Fatal("generated secret leaked into environment-file retry result")
	}
}

func TestMCPConsumeIntoApprovedProcessDoesNotReturnPlaintext(t *testing.T) {
	const canary = "MCP_CONSUMER_CANARY_private-message"
	link, envelope, contentHash := encryptedMCPTestMessage(t, canary, nil)
	resultFile := filepath.Join(t.TempDir(), "child-result")
	t.Setenv("MCP_HELPER_MODE", "consumer_success")
	t.Setenv("MCP_HELPER_RESULT", resultFile)
	profile, err := resolveMCPProcessProfile("test-consumer", mcpProcessProfile{
		Role:             "consumer",
		Executable:       os.Args[0],
		FixedArgs:        []string{"-test.run=^TestMCPProducerHelperProcess$"},
		AllowedSecretEnv: []string{"TARGET_SECRET"},
		InheritEnv:       []string{"MCP_HELPER_MODE", "MCP_HELPER_RESULT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets++
		writer.Header().Set("X-Wipe-Content-Hash", contentHash)
		writer.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = writer.Write(envelope)
	}))
	defer server.Close()
	policy := mcpPolicy{
		processProfiles:   map[string]mcpResolvedProcessProfile{"test-consumer": profile},
		recoveryDirectory: filepath.Join(t.TempDir(), "recovery"), recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5,
	}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "consume_into_process_env",
		Arguments: map[string]any{
			"private_link": link,
			"profile":      "test-consumer",
			"environment":  []map[string]any{{"name": "TARGET_SECRET"}},
		},
	})
	if err != nil || result.IsError || gets != 1 {
		t.Fatalf("err=%v gets=%d result=%#v", err, gets, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) {
		t.Fatalf("consumer plaintext leaked into MCP result: %s", wire)
	}
	childValue, err := os.ReadFile(resultFile)
	if err != nil || string(childValue) != canary {
		t.Fatalf("child value=%q err=%v", childValue, err)
	}
}

func TestMCPHostModeConsumesIntoDirectCommandWithoutProfile(t *testing.T) {
	const canary = "MCP_HOST_CONSUMER_CANARY_private-message"
	link, envelope, contentHash := encryptedMCPTestMessage(t, canary, nil)
	resultFile := filepath.Join(t.TempDir(), "child-result")
	t.Setenv("MCP_HELPER_MODE", "consumer_success")
	t.Setenv("MCP_HELPER_RESULT", resultFile)
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets++
		writer.Header().Set("X-Wipe-Content-Hash", contentHash)
		writer.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = writer.Write(envelope)
	}))
	defer server.Close()
	policy := mcpPolicy{
		accessMode: mcpAccessHost, recoveryDirectory: filepath.Join(t.TempDir(), "recovery"),
		recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5,
	}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "consume_into_process_env",
		Arguments: map[string]any{
			"private_link": link,
			"command":      os.Args[0],
			"arguments":    []string{"-test.run=^TestMCPProducerHelperProcess$"},
			"environment":  []map[string]any{{"name": "TARGET_SECRET"}},
		},
	})
	if err != nil || result.IsError || gets != 1 {
		t.Fatalf("err=%v gets=%d result=%#v", err, gets, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(canary)) {
		t.Fatalf("host consumer plaintext leaked into MCP result: %s", wire)
	}
	childValue, err := os.ReadFile(resultFile)
	if err != nil || string(childValue) != canary {
		t.Fatalf("child value=%q err=%v", childValue, err)
	}
}

func TestMCPRestrictedModeRejectsDirectCommandBeforeConsumption(t *testing.T) {
	link, _, _ := encryptedMCPTestMessage(t, "not consumed", nil)
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gets++
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	policy := mcpPolicy{accessMode: mcpAccessRestricted, recoveryDirectory: filepath.Join(t.TempDir(), "recovery"), recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, config{APIEndpoint: server.URL})
	defer cleanup()
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "consume_into_process_env",
		Arguments: map[string]any{
			"private_link": link,
			"command":      os.Args[0],
			"environment":  []map[string]any{{"name": "TARGET_SECRET"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(result)
	if !result.IsError || !bytes.Contains(wire, []byte("profile_argument_rejected")) || gets != 0 {
		t.Fatalf("result=%s gets=%d", wire, gets)
	}
}

func TestMCPGeneratedSecretRetryReusesSecretAndReleasesLinkOnlyAfterSuccess(t *testing.T) {
	resultFile := filepath.Join(t.TempDir(), "child-result")
	t.Setenv("MCP_HELPER_MODE", "consumer_fail")
	t.Setenv("MCP_HELPER_RESULT", resultFile)
	profile, err := resolveMCPProcessProfile("test-consumer", mcpProcessProfile{
		Role:             "consumer",
		Executable:       os.Args[0],
		FixedArgs:        []string{"-test.run=^TestMCPProducerHelperProcess$"},
		AllowedSecretEnv: []string{"TARGET_SECRET"},
		InheritEnv:       []string{"MCP_HELPER_MODE", "MCP_HELPER_RESULT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	puts := 0
	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut {
			t.Errorf("unexpected method %s", request.Method)
		}
		puts++
		uploaded, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":%q,"created":true}`, strings.TrimPrefix(request.URL.Path, "/api/messages/"))
	}))
	defer server.Close()
	recoveryDir := filepath.Join(t.TempDir(), "recovery")
	policy := mcpPolicy{
		processProfiles:   map[string]mcpResolvedProcessProfile{"test-consumer": profile},
		recoveryDirectory: recoveryDir, recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5,
	}
	settings := config{APIEndpoint: server.URL, SiteURL: "https://wipe.me", Expires: 24 * time.Hour}
	client, cleanup := connectMCPTestClientWithConfig(t, policy, settings)
	defer cleanup()
	first, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name: "generate_secret_into_process_env",
		Arguments: map[string]any{
			"profile":          "test-consumer",
			"environment_name": "TARGET_SECRET",
			"length":           24,
			"chars":            "base58",
		},
	})
	if err != nil || first.IsError || puts != 1 {
		t.Fatalf("err=%v puts=%d result=%#v", err, puts, first)
	}
	var pending mcpProcessExecutionOutput
	structured, _ := json.Marshal(first.StructuredContent)
	if err := json.Unmarshal(structured, &pending); err != nil || pending.Status != "execution_failed" || pending.RecoveryHandle == "" || pending.PrivateLink != "" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	t.Setenv("MCP_HELPER_MODE", "consumer_success")
	retried, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "retry_process_env",
		Arguments: map[string]any{"recovery_handle": pending.RecoveryHandle, "include_qr": true},
	})
	if err != nil || retried.IsError || puts != 1 {
		t.Fatalf("err=%v puts=%d result=%#v", err, puts, retried)
	}
	var completed mcpProcessExecutionOutput
	structured, _ = json.Marshal(retried.StructuredContent)
	if err := json.Unmarshal(structured, &completed); err != nil || completed.Status != "executed" || completed.PrivateLink == "" || !completed.QRIncluded {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	childValue, err := os.ReadFile(resultFile)
	if err != nil || len(childValue) != 24 {
		t.Fatalf("child value length=%d err=%v", len(childValue), err)
	}
	application, err := wipeme.ParseApplicationPrivateLink(completed.PrivateLink)
	if err != nil {
		t.Fatal(err)
	}
	messageID, secret, _ := application.EnvelopeCryptoParameters()
	decrypted, err := wipeme.Decrypt(bytes.NewReader(uploaded), messageID, secret)
	if err != nil {
		t.Fatal(err)
	}
	generated, ok := selectText(parseDocument(decrypted.Manifest.Message), -1)
	if !ok || generated != string(childValue) {
		t.Fatal("retry did not reuse the originally uploaded generated secret")
	}
	wire, _ := json.Marshal(retried)
	if bytes.Contains(wire, childValue) {
		t.Fatal("generated secret leaked into successful retry result")
	}
	entries, err := os.ReadDir(recoveryDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("recovery entries=%#v err=%v", entries, err)
	}
}

func TestMCPForgetGeneratedRecoveryDeletesRemoteBeforeLocalRecord(t *testing.T) {
	deletes := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		deletes++
		if request.Method != http.MethodDelete || request.Header.Get("X-Wipe-Deletion-Key") == "" {
			t.Errorf("unexpected request: %s %#v", request.Method, request.Header)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"deleted":true}`))
	}))
	defer server.Close()
	application, err := wipeme.ParseApplicationPrivateLink(testAutomaticLink)
	if err != nil {
		t.Fatal(err)
	}
	policy := mcpPolicy{recoveryDirectory: filepath.Join(t.TempDir(), "recovery"), recoveryTTL: 15 * time.Minute, recoveryMaxAttempts: 5}
	settings := config{APIEndpoint: server.URL}
	client, cleanup, store := connectMCPTestClientRuntime(t, policy, settings)
	defer cleanup()
	handle, err := store.create(&mcpRecoveryRecord{
		Type: "generate_process", MessageID: application.MessageID, Secret: application.Secret,
		Candidates: []string{application.Secret}, PrivateLink: testAutomaticLink, GeneratedSecret: "not-returned", Attempt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "forget_recovery",
		Arguments: map[string]any{"recovery_handle": handle},
	})
	if err != nil || result.IsError || deletes != 1 {
		t.Fatalf("err=%v deletes=%d result=%#v", err, deletes, result)
	}
	wire, _ := json.Marshal(result)
	if bytes.Contains(wire, []byte(testAutomaticLink)) || bytes.Contains(wire, []byte("not-returned")) {
		t.Fatalf("recovery capability leaked: %s", wire)
	}
	if _, err := os.Stat(store.recordPath(handle)); !os.IsNotExist(err) {
		t.Fatalf("recovery record still exists: %v", err)
	}
}

func TestMCPProducerHelperProcess(t *testing.T) {
	mode := os.Getenv("MCP_HELPER_MODE")
	if mode == "" {
		return
	}
	if strings.HasPrefix(mode, "consumer_") {
		if mode == "consumer_success" {
			_ = os.WriteFile(os.Getenv("MCP_HELPER_RESULT"), []byte(os.Getenv("TARGET_SECRET")), 0o600)
			os.Exit(0)
		}
		os.Exit(7)
	}
	_, _ = fmt.Fprint(os.Stdout, os.Getenv("MCP_HELPER_SECRET"))
	if mode == "fail" {
		os.Exit(7)
	}
	os.Exit(0)
}

func encryptedMCPTestMessage(t *testing.T, message string, attachments []wipeme.AttachmentInput) (string, []byte, string) {
	t.Helper()
	application, err := wipeme.ParseApplicationPrivateLink(testAutomaticLink)
	if err != nil {
		t.Fatal(err)
	}
	messageID, secret, err := application.EnvelopeCryptoParameters()
	if err != nil {
		t.Fatal(err)
	}
	var envelope bytes.Buffer
	encrypted, err := wipeme.Encrypt(&envelope, messageID, secret, message, attachments)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(encrypted.DeletionKey[:])
	return testAutomaticLink, envelope.Bytes(), encrypted.ContentHash
}

func TestMCPConfigRejectsUnknownAndInsecurePolicyFiles(t *testing.T) {
	clearConfigEnvironment(t)
	known := writeTestConfig(t, "mcp:\n  access_mode: restricted\n")
	loaded, err := loadBaseConfig([]string{"--config", known})
	if err != nil || loaded.MCP == nil || loaded.MCP.AccessMode != mcpAccessRestricted {
		t.Fatalf("load access mode: config=%#v err=%v", loaded.MCP, err)
	}

	unknown := writeTestConfig(t, "mcp:\n  allowed_reed_roots: []\n")
	if _, err := loadBaseConfig([]string{"--config", unknown}); err == nil {
		t.Fatal("expected unknown MCP configuration field to fail")
	}

	insecure := writeTestConfig(t, "mcp: {}\n")
	if err := os.Chmod(insecure, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := validateMCPConfigFiles([]string{"--config", insecure}); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("expected insecure configuration error, got %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"mcp", "--config", known, "--access", "invalid"}, bytes.NewReader(nil), &stdout, &stderr, "test"); code == 0 || !strings.Contains(stderr.String(), "host or restricted") {
		t.Fatalf("expected invalid access flag error: code=%d stderr=%q", code, stderr.String())
	}
}

func connectMCPTestClient(t *testing.T, policy mcpPolicy) (*mcpsdk.ClientSession, func()) {
	return connectMCPTestClientWithConfig(t, policy, config{})
}

func connectMCPTestClientWithConfig(t *testing.T, policy mcpPolicy, settings config) (*mcpsdk.ClientSession, func()) {
	client, cleanup, _ := connectMCPTestClientRuntime(t, policy, settings)
	return client, cleanup
}

func canonicalTestPath(t *testing.T, value string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		t.Fatalf("resolve test path %q: %v", value, err)
	}
	return filepath.Clean(resolved)
}

func TestMCPRecoveryCanonicalizesAncestorAliasesButRejectsFinalSymlink(t *testing.T) {
	realParent := t.TempDir()
	aliasParent := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Skipf("create ancestor alias: %v", err)
	}
	store := &mcpRecoveryStore{directory: filepath.Join(aliasParent, "recovery")}
	if err := store.prepare(); err != nil {
		t.Fatalf("prepare through ancestor alias: %v", err)
	}
	want := filepath.Join(canonicalTestPath(t, realParent), "recovery")
	if store.directory != want {
		t.Fatalf("canonical recovery directory=%q want=%q", store.directory, want)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	finalAlias := filepath.Join(t.TempDir(), "recovery")
	if err := os.Symlink(target, finalAlias); err != nil {
		t.Skipf("create final alias: %v", err)
	}
	unsafe := &mcpRecoveryStore{directory: finalAlias}
	if err := unsafe.prepare(); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("final recovery symlink was not rejected: %v", err)
	}
}

func connectMCPTestClientRuntime(t *testing.T, policy mcpPolicy, settings config) (*mcpsdk.ClientSession, func(), *mcpRecoveryStore) {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	if policy.recoveryDirectory == "" {
		policy.recoveryDirectory = t.TempDir()
	}
	if policy.recoveryTTL == 0 {
		policy.recoveryTTL = 15 * time.Minute
	}
	if policy.recoveryMaxAttempts == 0 {
		policy.recoveryMaxAttempts = 5
	}
	store := newMCPRecoveryStore(policy)
	if err := store.prepare(); err != nil {
		t.Fatal(err)
	}
	serverSession, err := newMCPServer(policy, settings, store, "test").Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "wipeme-test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatal(err)
	}
	return clientSession, func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	}, store
}
