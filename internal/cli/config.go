package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	defaultServerURL = "https://wipe.me"
	systemConfigPath = "/etc/wipeme/config.yaml"
)

type yamlConfig struct {
	ServerURL string `yaml:"server_url"`
	APIURL    string `yaml:"api_url"`
	SiteURL   string `yaml:"site_url"`
	Expires   string `yaml:"expires"`
	Copy      *bool  `yaml:"copy"`
}

func loadBaseConfig(args []string) (config, error) {
	explicitPath, explicit, err := selectedConfigPath(args)
	if err != nil {
		return config{}, err
	}

	var loaded yamlConfig
	if explicit {
		if err := mergeYAMLConfig(&loaded, explicitPath, true); err != nil {
			return config{}, err
		}
	} else {
		if err := mergeYAMLConfig(&loaded, systemConfigPath, false); err != nil {
			return config{}, err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return config{}, fmt.Errorf("find home directory: %w", err)
		}
		if err := mergeYAMLConfig(&loaded, filepath.Join(home, ".wipeme", "config.yaml"), false); err != nil {
			return config{}, err
		}
	}

	serverURL := valueOrDefault(loaded.ServerURL, defaultServerURL)
	if value := strings.TrimSpace(os.Getenv("WIPEME_SERVER_URL")); value != "" {
		serverURL = value
	}

	apiConfigured := loaded.APIURL != ""
	apiURL := valueOrDefault(loaded.APIURL, serverURL)
	if value := strings.TrimSpace(os.Getenv("WIPEME_API_URL")); value != "" {
		apiURL = value
		apiConfigured = true
	}
	siteConfigured := loaded.SiteURL != ""
	siteURL := valueOrDefault(loaded.SiteURL, serverURL)
	if value := strings.TrimSpace(os.Getenv("WIPEME_SITE_URL")); value != "" {
		siteURL = value
		siteConfigured = true
	}

	expires := 24 * time.Hour
	if loaded.Expires != "" {
		expires, err = parseDuration(loaded.Expires)
		if err != nil {
			return config{}, fmt.Errorf("config expires: %w", err)
		}
	}
	if value := strings.TrimSpace(os.Getenv("WIPEME_EXPIRES")); value != "" {
		expires, err = parseDuration(value)
		if err != nil {
			return config{}, fmt.Errorf("WIPEME_EXPIRES: %w", err)
		}
	}

	copyLink := loaded.Copy != nil && *loaded.Copy
	if value := strings.TrimSpace(os.Getenv("WIPEME_COPY")); value != "" {
		copyLink, err = strconv.ParseBool(value)
		if err != nil {
			return config{}, fmt.Errorf("WIPEME_COPY must be true or false")
		}
	}

	return config{
		ServerURL:      serverURL,
		APIEndpoint:    apiURL,
		SiteURL:        siteURL,
		Expires:        expires,
		Copy:           copyLink,
		ConfigPath:     explicitPath,
		APIConfigured:  apiConfigured,
		SiteConfigured: siteConfigured,
	}, nil
}

func selectedConfigPath(args []string) (string, bool, error) {
	selected := ""
	found := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--config" || argument == "-config" {
			if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" {
				return "", false, fmt.Errorf("%s requires a path", argument)
			}
			selected, found = args[index+1], true
			index++
			continue
		}
		if value, ok := strings.CutPrefix(argument, "--config="); ok {
			if strings.TrimSpace(value) == "" {
				return "", false, fmt.Errorf("--config requires a path")
			}
			selected, found = value, true
			continue
		}
		if value, ok := strings.CutPrefix(argument, "-config="); ok {
			if strings.TrimSpace(value) == "" {
				return "", false, fmt.Errorf("-config requires a path")
			}
			selected, found = value, true
		}
	}
	if found {
		return selected, true, nil
	}
	if value := strings.TrimSpace(os.Getenv("WIPEME_CONFIG")); value != "" {
		return value, true, nil
	}
	return "", false, nil
}

func mergeYAMLConfig(target *yamlConfig, path string, required bool) error {
	handle, err := os.Open(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open config %q: %w", path, err)
	}
	defer handle.Close()

	var value yamlConfig
	decoder := yaml.NewDecoder(handle)
	decoder.KnownFields(true)
	if err := decoder.Decode(&value); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode config %q: multiple YAML documents are not supported", path)
		}
		return fmt.Errorf("decode config %q: %w", path, err)
	}

	if value.ServerURL != "" {
		target.ServerURL = strings.TrimSpace(value.ServerURL)
	}
	if value.APIURL != "" {
		target.APIURL = strings.TrimSpace(value.APIURL)
	}
	if value.SiteURL != "" {
		target.SiteURL = strings.TrimSpace(value.SiteURL)
	}
	if value.Expires != "" {
		target.Expires = strings.TrimSpace(value.Expires)
	}
	if value.Copy != nil {
		target.Copy = value.Copy
	}
	return nil
}

func parseDuration(input string) (time.Duration, error) {
	input = strings.TrimSpace(input)
	if strings.HasSuffix(input, "d") && strings.Count(input, "d") == 1 {
		days, err := strconv.ParseFloat(strings.TrimSuffix(input, "d"), 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", input)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	parsed, err := time.ParseDuration(input)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}
