package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/sdk/go/wipeme"
)

const mcpInstructions = "Wipe.me tools consume one-time messages and never return plaintext, decrypted attachments, generated secrets, passphrases, environment values, or process output. In host access mode, process tools execute direct argv commands under the MCP host's OS, container, sandbox, and approval policy; in restricted access mode they execute only administrator-approved profiles. Private links and QR images are bearer capabilities and may be retained by the MCP host transcript. Retrieval consumes the remote message; retry-capable tools use protected local recovery records. Prefer environment-file tools for commands that may be retried or repeated and for Docker or Docker Compose. Use process tools only for one immediate execution when a persistent private file is undesirable."

const (
	mcpAccessHost       = "host"
	mcpAccessRestricted = "restricted"
)

type mcpPolicy struct {
	accessMode            string
	allowedReadRoots      []string
	allowedWriteRoots     []string
	allowedLinkEnv        map[string]struct{}
	allowedPassphraseEnv  map[string]struct{}
	allowedSourceEnv      map[string]struct{}
	recoveryDirectory     string
	recoveryTTL           time.Duration
	recoveryMaxAttempts   int
	maxEnvironmentSources int
	processProfiles       map[string]mcpResolvedProcessProfile
}

type mcpResolvedProcessProfile struct {
	role              string
	executable        string
	fixedArgs         []string
	argumentPatterns  []*regexp.Regexp
	maxArguments      int
	workingDirectory  string
	timeout           time.Duration
	acceptedExitCodes map[int]struct{}
	allowedSecretEnv  map[string]struct{}
	inheritEnv        []string
	maxStdoutBytes    int64
	allowAnySecretEnv bool
	inheritAllEnv     bool
}

type inspectPrivateLinkInput struct {
	PrivateLink string `json:"private_link,omitempty" jsonschema:"Direct private link. Prefer link_file for agent workflows."`
	LinkFile    string `json:"link_file,omitempty" jsonschema:"Absolute path to a protected file containing the private link."`
	LinkEnv     string `json:"link_env,omitempty" jsonschema:"Server environment variable containing the private link; restricted mode requires it in allowed_link_env."`
}

type inspectPrivateLinkResult struct {
	Valid                      bool   `json:"valid"`
	ReasonCode                 string `json:"reason_code,omitempty"`
	MessageID                  string `json:"message_id,omitempty"`
	Mode                       string `json:"mode,omitempty"`
	HasFragmentSecret          bool   `json:"has_fragment_secret,omitempty"`
	RequiresExternalPassphrase bool   `json:"requires_external_passphrase,omitempty"`
}

type mcpPolicySummary struct {
	AccessMode            string   `json:"access_mode"`
	AccessSource          string   `json:"access_source"`
	ConfigFiles           []string `json:"config_files,omitempty"`
	RestrictedAllowlists  bool     `json:"restricted_allowlists_active"`
	AllowedReadRoots      []string `json:"allowed_read_roots,omitempty"`
	AllowedWriteRoots     []string `json:"allowed_write_roots,omitempty"`
	AllowedLinkEnv        []string `json:"allowed_link_env,omitempty"`
	AllowedPassphraseEnv  []string `json:"allowed_passphrase_env,omitempty"`
	AllowedSourceEnv      []string `json:"allowed_source_env,omitempty"`
	ProcessProfiles       []string `json:"process_profiles,omitempty"`
	DirectProcessCommands bool     `json:"direct_process_commands"`
	RecoveryDirectory     string   `json:"recovery_directory"`
	RecoveryTTL           string   `json:"recovery_ttl"`
	RecoveryMaxAttempts   int      `json:"recovery_max_attempts"`
	MaxEnvironmentSources int      `json:"max_environment_sources"`
}

func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) error {
	flags := flag.NewFlagSet("wipeme mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := ""
	accessMode := ""
	showPolicy := false
	showVersion := false
	flags.StringVar(&configPath, "config", "", "configuration file")
	flags.StringVar(&accessMode, "access", "", "access policy: host or restricted (default host)")
	flags.BoolVar(&showPolicy, "show-policy", false, "print the effective non-secret MCP policy and exit")
	flags.BoolVar(&showVersion, "version", false, "print the version and exit before starting MCP")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: wipeme mcp [options]")
		fmt.Fprintln(stderr, "\nRun the agent-safe Wipe.me MCP server over stdio.\n\nOptions:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fail(exitUsage, "%v", err)
	}
	if flags.NArg() != 0 {
		return fail(exitUsage, "wipeme mcp does not accept positional arguments")
	}
	if showVersion {
		_, err := fmt.Fprintf(stdout, "wipeme %s\n", version)
		return err
	}

	configArgs := args
	if configPath != "" {
		configArgs = []string{"--config", configPath}
	}
	settings, err := loadBaseConfig(configArgs)
	if err != nil {
		return err
	}
	if err := validateMCPConfigFiles(configArgs); err != nil {
		return err
	}
	policy, err := resolveMCPPolicy(settings.MCP, accessMode)
	if err != nil {
		return err
	}
	if showPolicy {
		configFiles, err := mcpConfigPaths(configArgs)
		if err != nil {
			return err
		}
		return writeMCPPolicySummary(stdout, policy, settings.MCP, accessMode, configFiles)
	}

	store := newMCPRecoveryStore(policy)
	if err := store.prepare(); err != nil {
		return err
	}
	initialCleanupContext, cancelInitialCleanup := context.WithTimeout(context.Background(), 30*time.Second)
	cleanupMCPRecovery(initialCleanupContext, store, settings)
	cancelInitialCleanup()
	server := newMCPServer(policy, settings, store, version)
	transport := &mcpsdk.IOTransport{
		Reader: readNoCloser{Reader: stdin},
		Writer: writeNoCloser{Writer: stdout},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		interval := time.Minute
		if policy.recoveryTTL/2 < interval {
			interval = policy.recoveryTTL / 2
		}
		if interval < time.Second {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cleanupMCPRecovery(ctx, store, settings)
			case <-ctx.Done():
				shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
				cleanupMCPRecovery(shutdownContext, store, settings)
				cancelShutdown()
				return
			}
		}
	}()
	err = server.Run(ctx, transport)
	cancel()
	<-cleanupDone
	if err != nil {
		return errors.New("MCP server stopped because the protocol stream failed")
	}
	return nil
}

func writeMCPPolicySummary(writer io.Writer, policy mcpPolicy, configured *mcpYAMLConfig, accessOverride string, configFiles []string) error {
	source := "default"
	if configured != nil && strings.TrimSpace(configured.AccessMode) != "" {
		source = "configuration"
	}
	if strings.TrimSpace(accessOverride) != "" {
		source = "command_line"
	}
	summary := mcpPolicySummary{
		AccessMode: policy.accessMode, AccessSource: source, ConfigFiles: append([]string(nil), configFiles...),
		RestrictedAllowlists: policy.accessMode == mcpAccessRestricted,
		ProcessProfiles:      mapKeys(policy.processProfiles), RecoveryDirectory: policy.recoveryDirectory,
		DirectProcessCommands: policy.accessMode == mcpAccessHost,
		RecoveryTTL:           policy.recoveryTTL.String(), RecoveryMaxAttempts: policy.recoveryMaxAttempts,
		MaxEnvironmentSources: policy.maxEnvironmentSources,
	}
	if summary.RestrictedAllowlists {
		summary.AllowedReadRoots = append([]string(nil), policy.allowedReadRoots...)
		summary.AllowedWriteRoots = append([]string(nil), policy.allowedWriteRoots...)
		summary.AllowedLinkEnv = mapKeys(policy.allowedLinkEnv)
		summary.AllowedPassphraseEnv = mapKeys(policy.allowedPassphraseEnv)
		summary.AllowedSourceEnv = mapKeys(policy.allowedSourceEnv)
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "%s\n", encoded)
	return err
}

func mapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func newMCPServer(policy mcpPolicy, settings config, store *mcpRecoveryStore, version string) *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:        "wipeme",
		Title:       "Wipe.me agent-safe tools",
		Description: "Local tools for creating and applying private one-time messages without returning plaintext.",
		Version:     version,
		WebsiteURL:  "https://wipe.me",
	}, &mcpsdk.ServerOptions{
		Instructions: mcpInstructions,
		Capabilities: &mcpsdk.ServerCapabilities{},
	})

	readOnly, destructive, closedWorld := true, false, false
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "inspect_private_link",
		Title:       "Inspect a private link",
		Description: "Validate a Wipe.me private link locally without contacting the service or echoing the complete link.",
		Annotations: &mcpsdk.ToolAnnotations{
			Title:           "Inspect a private link",
			ReadOnlyHint:    readOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  true,
			OpenWorldHint:   &closedWorld,
		},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input inspectPrivateLinkInput) (*mcpsdk.CallToolResult, inspectPrivateLinkResult, error) {
		result, err := inspectPrivateLink(policy, input)
		return nil, result, err
	})
	registerMCPCreationTools(server, policy, settings)
	registerMCPDeleteTool(server, policy, settings)
	registerMCPFileConsumptionTools(server, policy, settings, store)
	registerMCPEnvFileTools(server, policy, settings, store)
	registerMCPProcessConsumptionTools(server, policy, settings, store)
	registerMCPForgetRecoveryTool(server, settings, store)

	return server
}

func inspectPrivateLink(policy mcpPolicy, input inspectPrivateLinkInput) (inspectPrivateLinkResult, error) {
	value, err := resolveMCPLinkSource(policy, input)
	if err != nil {
		return inspectPrivateLinkResult{}, err
	}
	defer func() { value = "" }()

	link, err := wipeme.ParseApplicationPrivateLink(value)
	if err != nil {
		return inspectPrivateLinkResult{Valid: false, ReasonCode: classifyPrivateLinkError(value)}, nil
	}
	mode := "automatic"
	if link.CustomPassphrase {
		mode = "manual"
	}
	return inspectPrivateLinkResult{
		Valid:                      true,
		MessageID:                  link.MessageID,
		Mode:                       mode,
		HasFragmentSecret:          !link.CustomPassphrase && link.Secret != "",
		RequiresExternalPassphrase: link.CustomPassphrase,
	}, nil
}

func resolveMCPLinkSource(policy mcpPolicy, input inspectPrivateLinkInput) (string, error) {
	return resolveMCPLinkValues(policy, input.PrivateLink, input.LinkFile, input.LinkEnv)
}

func resolveMCPLinkValues(policy mcpPolicy, privateLink, linkFile, linkEnv string) (string, error) {
	count := 0
	if privateLink != "" {
		count++
	}
	if linkFile != "" {
		count++
	}
	if linkEnv != "" {
		count++
	}
	if count != 1 {
		return "", errors.New("link_source_conflict: provide exactly one private link source")
	}
	if privateLink != "" {
		return privateLink, nil
	}
	if linkFile != "" {
		path, err := policy.validateReadFile(linkFile)
		if err != nil {
			return "", fmt.Errorf("%w: link file is unavailable", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", errors.New("invalid_link: link file is unavailable")
		}
		defer wipe(data)
		return trimLine(string(data)), nil
	}
	if !mcpEnvironmentAllowed(policy, policy.allowedLinkEnv, linkEnv) {
		return "", errors.New("invalid_link: link environment source is not allowed")
	}
	value, ok := os.LookupEnv(linkEnv)
	if !ok || value == "" {
		return "", errors.New("invalid_link: link environment source is unavailable")
	}
	return value, nil
}

func classifyPrivateLinkError(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "invalid_url"
	}
	id := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	if _, err9 := wipeme.NormalizeBase58(id, wipeme.AutomaticMessageIDLength); err9 != nil {
		if _, err8 := wipeme.NormalizeBase58(id, wipeme.CustomMessageIDLength); err8 != nil {
			return "invalid_message_id"
		}
	}
	return "invalid_fragment"
}

func resolveMCPPolicy(value *mcpYAMLConfig, accessOverride string) (mcpPolicy, error) {
	policy := mcpPolicy{
		accessMode:            mcpAccessHost,
		allowedLinkEnv:        map[string]struct{}{},
		allowedPassphraseEnv:  map[string]struct{}{},
		allowedSourceEnv:      map[string]struct{}{},
		recoveryTTL:           15 * time.Minute,
		recoveryMaxAttempts:   5,
		maxEnvironmentSources: 16,
		processProfiles:       map[string]mcpResolvedProcessProfile{},
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return mcpPolicy{}, fmt.Errorf("resolve MCP recovery directory: %w", err)
	}
	policy.recoveryDirectory = filepath.Join(home, ".local", "state", "wipeme", "mcp-recovery")
	if value != nil && value.AccessMode != "" {
		policy.accessMode = strings.ToLower(strings.TrimSpace(value.AccessMode))
	}
	if accessOverride != "" {
		policy.accessMode = strings.ToLower(strings.TrimSpace(accessOverride))
	}
	if policy.accessMode != mcpAccessHost && policy.accessMode != mcpAccessRestricted {
		return mcpPolicy{}, fmt.Errorf("MCP access policy must be host or restricted")
	}
	if value == nil {
		return policy, nil
	}
	if policy.accessMode == mcpAccessRestricted {
		if policy.allowedReadRoots, err = normalizeMCPRoots(value.AllowedReadRoots); err != nil {
			return mcpPolicy{}, err
		}
		if policy.allowedWriteRoots, err = normalizeMCPRoots(value.AllowedWriteRoots); err != nil {
			return mcpPolicy{}, err
		}
		for _, item := range []struct {
			values []string
			target map[string]struct{}
			label  string
		}{
			{value.AllowedLinkEnv, policy.allowedLinkEnv, "allowed_link_env"},
			{value.AllowedPassphraseEnv, policy.allowedPassphraseEnv, "allowed_passphrase_env"},
			{value.AllowedSourceEnv, policy.allowedSourceEnv, "allowed_source_env"},
		} {
			for _, name := range item.values {
				if !envName.MatchString(name) {
					return mcpPolicy{}, fmt.Errorf("mcp.%s contains an invalid environment name", item.label)
				}
				item.target[name] = struct{}{}
			}
		}
	}
	if value.RecoveryDirectory != "" {
		policy.recoveryDirectory, err = normalizeAbsolutePath(value.RecoveryDirectory)
		if err != nil {
			return mcpPolicy{}, fmt.Errorf("mcp.recovery_directory must be absolute")
		}
	}
	if value.RecoveryTTL != "" {
		policy.recoveryTTL, err = parseDuration(value.RecoveryTTL)
		if err != nil || policy.recoveryTTL <= 0 {
			return mcpPolicy{}, fmt.Errorf("mcp.recovery_ttl must be positive")
		}
	}
	if value.RecoveryMaxAttempts != nil {
		if *value.RecoveryMaxAttempts < 1 || *value.RecoveryMaxAttempts > 100 {
			return mcpPolicy{}, fmt.Errorf("mcp.recovery_max_attempts must be between 1 and 100")
		}
		policy.recoveryMaxAttempts = *value.RecoveryMaxAttempts
	}
	if value.MaxEnvironmentSources != nil {
		if *value.MaxEnvironmentSources < 1 || *value.MaxEnvironmentSources > 128 {
			return mcpPolicy{}, fmt.Errorf("mcp.max_environment_sources must be between 1 and 128")
		}
		policy.maxEnvironmentSources = *value.MaxEnvironmentSources
	}
	if value.ProcessProfiles != nil {
		for name, profile := range value.ProcessProfiles {
			resolved, err := resolveMCPProcessProfile(name, profile)
			if err != nil {
				return mcpPolicy{}, err
			}
			policy.processProfiles[name] = resolved
		}
	}
	return policy, nil
}

var mcpProfileName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func resolveMCPProcessProfile(name string, value mcpProcessProfile) (mcpResolvedProcessProfile, error) {
	if !mcpProfileName.MatchString(name) {
		return mcpResolvedProcessProfile{}, errors.New("mcp.process_profiles contains an invalid profile name")
	}
	if value.Role != "producer" && value.Role != "consumer" {
		return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s.role must be producer or consumer", name)
	}
	executable, err := normalizeAbsolutePath(value.Executable)
	if err != nil {
		return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s.executable must be absolute", name)
	}
	base := strings.ToLower(filepath.Base(executable))
	for _, unsafe := range []string{"sh", "bash", "dash", "zsh", "fish", "env", "printenv"} {
		if base == unsafe {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s uses a prohibited executable", name)
		}
	}
	resolved := mcpResolvedProcessProfile{
		role:              value.Role,
		executable:        executable,
		fixedArgs:         append([]string(nil), value.FixedArgs...),
		maxArguments:      value.MaxArguments,
		timeout:           2 * time.Minute,
		acceptedExitCodes: map[int]struct{}{},
		allowedSecretEnv:  map[string]struct{}{},
		inheritEnv:        append([]string(nil), value.InheritEnv...),
		maxStdoutBytes:    value.MaxStdoutBytes,
	}
	if resolved.maxArguments < 0 || resolved.maxArguments > 128 {
		return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s.max_arguments is outside the supported range", name)
	}
	for _, pattern := range value.ArgumentPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s contains an invalid argument pattern", name)
		}
		resolved.argumentPatterns = append(resolved.argumentPatterns, compiled)
	}
	if value.WorkingDirectory != "" {
		resolved.workingDirectory, err = normalizeAbsolutePath(value.WorkingDirectory)
		if err != nil {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s.working_directory must be absolute", name)
		}
	}
	if value.Timeout != "" {
		resolved.timeout, err = parseDuration(value.Timeout)
		if err != nil || resolved.timeout <= 0 || resolved.timeout > time.Hour {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s.timeout is outside the supported range", name)
		}
	}
	exitCodes := value.AcceptedExitCodes
	if len(exitCodes) == 0 {
		exitCodes = []int{0}
	}
	for _, code := range exitCodes {
		if code < 0 || code > 255 {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s contains an invalid accepted exit code", name)
		}
		resolved.acceptedExitCodes[code] = struct{}{}
	}
	for _, env := range value.AllowedSecretEnv {
		if !envName.MatchString(env) || strings.HasPrefix(env, "WIPEME_") {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s contains an invalid secret environment name", name)
		}
		resolved.allowedSecretEnv[env] = struct{}{}
	}
	for _, env := range resolved.inheritEnv {
		if !envName.MatchString(env) || strings.HasPrefix(env, "WIPEME_") {
			return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s contains an invalid inherited environment name", name)
		}
	}
	if resolved.maxStdoutBytes == 0 {
		resolved.maxStdoutBytes = 65536
	}
	if resolved.maxStdoutBytes < 1 || resolved.maxStdoutBytes > 16*1024*1024 {
		return mcpResolvedProcessProfile{}, fmt.Errorf("mcp.process_profiles.%s.max_stdout_bytes is outside the supported range", name)
	}
	return resolved, nil
}

func normalizeMCPRoots(values []string) ([]string, error) {
	roots := make([]string, 0, len(values))
	for _, value := range values {
		root, err := normalizeAbsolutePath(value)
		if err != nil {
			return nil, fmt.Errorf("MCP allowed roots must be absolute directories")
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("MCP allowed root is unavailable")
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("MCP allowed root is unavailable")
		}
		roots = append(roots, filepath.Clean(resolved))
	}
	return roots, nil
}

func normalizeAbsolutePath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !filepath.IsAbs(value) {
		return "", errors.New("not absolute")
	}
	return filepath.Clean(value), nil
}

func validateMCPReadFile(value string, roots []string) (string, error) {
	return validateMCPReadFileWithAccess(value, roots, false)
}

func validateMCPReadFileWithAccess(value string, roots []string, hostAccess bool) (string, error) {
	path, err := normalizeAbsolutePath(value)
	if err != nil {
		return "", errors.New("path_outside_allowed_root")
	}
	if !hostAccess && !pathWithinRoots(path, roots) {
		return "", errors.New("path_outside_allowed_root")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("output_refused")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || (!hostAccess && !pathWithinRoots(resolved, roots)) {
		return "", errors.New("path_outside_allowed_root")
	}
	return resolved, nil
}

func (policy mcpPolicy) validateReadFile(value string) (string, error) {
	return validateMCPReadFileWithAccess(value, policy.allowedReadRoots, policy.accessMode == mcpAccessHost)
}

func mcpEnvironmentAllowed(policy mcpPolicy, allowed map[string]struct{}, name string) bool {
	if !envName.MatchString(name) {
		return false
	}
	if policy.accessMode == mcpAccessHost {
		return true
	}
	_, ok := allowed[name]
	return ok
}

func pathWithinRoots(path string, roots []string) bool {
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateMCPConfigFiles(args []string) error {
	paths, err := mcpConfigPaths(args)
	if err != nil {
		return err
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect MCP configuration: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("MCP configuration must be a regular file")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("MCP configuration must not be writable by group or others")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return fmt.Errorf("MCP configuration must be owned by the current user or root")
		}
	}
	return nil
}

func mcpConfigPaths(args []string) ([]string, error) {
	selected, explicit, err := selectedConfigPath(args)
	if err != nil {
		return nil, err
	}
	if explicit {
		return []string{selected}, nil
	}
	paths := []string{}
	if _, err := os.Stat(systemConfigPath); err == nil {
		paths = append(paths, systemConfigPath)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	userPath := filepath.Join(home, ".wipeme", "config.yaml")
	if _, err := os.Stat(userPath); err == nil {
		paths = append(paths, userPath)
	}
	return paths, nil
}

type readNoCloser struct{ io.Reader }

func (readNoCloser) Close() error { return nil }

type writeNoCloser struct{ io.Writer }

func (writeNoCloser) Close() error { return nil }
