package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigFileUsesServerURLAsAPIAndSiteDefault(t *testing.T) {
	clearConfigEnvironment(t)
	path := writeTestConfig(t, `
server_url: https://private.wipe.example
expires: 7d
copy: true
`)

	settings, _, err := parseFlags([]string{"--config", path}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.ServerURL != "https://private.wipe.example" || settings.APIEndpoint != settings.ServerURL || settings.SiteURL != settings.ServerURL {
		t.Fatalf("unexpected URL resolution: %#v", settings)
	}
	if settings.Expires != 7*24*time.Hour || !settings.Copy {
		t.Fatalf("unexpected file defaults: %#v", settings)
	}
}

func TestAPIAndSiteEnvironmentOverridesRemainIndependent(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("WIPEME_SERVER_URL", "https://shared.example")
	t.Setenv("WIPEME_API_URL", "http://localhost:8787")
	t.Setenv("WIPEME_SITE_URL", "http://localhost:5173")

	settings, _, err := parseFlags(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.ServerURL != "https://shared.example" || settings.APIEndpoint != "http://localhost:8787" || settings.SiteURL != "http://localhost:5173" {
		t.Fatalf("unexpected environment resolution: %#v", settings)
	}
}

func TestSiteEnvironmentDefaultsToResolvedServerURL(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("WIPEME_SERVER_URL", "https://staging.wipe.example")

	settings, _, err := parseFlags(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.APIEndpoint != settings.ServerURL || settings.SiteURL != settings.ServerURL {
		t.Fatalf("API and site should inherit server URL: %#v", settings)
	}
}

func TestExplicitAPIConfigSurvivesServerFlag(t *testing.T) {
	clearConfigEnvironment(t)
	path := writeTestConfig(t, "api_url: http://localhost:8787\n")

	settings, _, err := parseFlags([]string{"--config", path, "--server-url", "https://staging.wipe.example"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.APIEndpoint != "http://localhost:8787" || settings.SiteURL != "https://staging.wipe.example" {
		t.Fatalf("unexpected flag resolution: %#v", settings)
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	clearConfigEnvironment(t)
	path := writeTestConfig(t, "servre_url: https://typo.example\n")
	if _, _, err := parseFlags([]string{"--config", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected unknown YAML field to fail")
	}
}

func TestUserConfigLayerOverridesSystemConfig(t *testing.T) {
	system := writeTestConfig(t, `
server_url: https://system.example
api_url: https://system-api.example
expires: 1h
copy: true
`)
	user := writeTestConfig(t, `
server_url: https://user.example
expires: 2h
copy: false
`)

	var merged yamlConfig
	if err := mergeYAMLConfig(&merged, system, true); err != nil {
		t.Fatal(err)
	}
	if err := mergeYAMLConfig(&merged, user, true); err != nil {
		t.Fatal(err)
	}
	if merged.ServerURL != "https://user.example" || merged.APIURL != "https://system-api.example" || merged.Expires != "2h" || merged.Copy == nil || *merged.Copy {
		t.Fatalf("unexpected layered config: %#v", merged)
	}
}

func TestConfigRequiresExplicitFileToExist(t *testing.T) {
	clearConfigEnvironment(t)
	path := filepath.Join(t.TempDir(), "missing.yaml")
	if _, _, err := parseFlags([]string{"--config", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected missing explicit config to fail")
	}
}

func writeTestConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"WIPEME_SERVER_URL",
		"WIPEME_API_URL",
		"WIPEME_SITE_URL",
		"WIPEME_EXPIRES",
		"WIPEME_COPY",
	} {
		t.Setenv(name, "")
	}
	empty := filepath.Join(t.TempDir(), "empty-config.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WIPEME_CONFIG", empty)
}
