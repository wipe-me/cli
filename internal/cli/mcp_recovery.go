package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

const mcpRecoveryVersion = 1

type mcpRecoveryRecord struct {
	Version          int                     `json:"version"`
	Type             string                  `json:"type"`
	ExpiresAt        time.Time               `json:"expires_at"`
	Attempt          int                     `json:"attempt"`
	Envelope         []byte                  `json:"envelope,omitempty"`
	MessageID        string                  `json:"message_id,omitempty"`
	Secret           string                  `json:"secret,omitempty"`
	Manual           bool                    `json:"manual,omitempty"`
	Candidates       []string                `json:"candidates,omitempty"`
	Profile          string                  `json:"profile,omitempty"`
	Command          string                  `json:"command,omitempty"`
	Arguments        []string                `json:"arguments,omitempty"`
	Environment      []mcpEnvironmentMapping `json:"environment,omitempty"`
	EnvironmentName  string                  `json:"environment_name,omitempty"`
	DestinationFile  string                  `json:"destination_file,omitempty"`
	EnvFileFormat    string                  `json:"env_file_format,omitempty"`
	Overwrite        bool                    `json:"overwrite,omitempty"`
	GeneratedSecret  string                  `json:"generated_secret,omitempty"`
	PrivateLink      string                  `json:"private_link,omitempty"`
	MessageExpiresAt string                  `json:"message_expires_at,omitempty"`
	AttachmentCount  int                     `json:"attachment_count,omitempty"`
	CreatorSecret    string                  `json:"creator_secret,omitempty"`
	ReceiptFile      string                  `json:"receipt_file,omitempty"`
	LinkFile         string                  `json:"link_file,omitempty"`
}

type mcpRecoveryStore struct {
	directory   string
	ttl         time.Duration
	maxAttempts int
}

type mcpRecoveryLease struct {
	store  *mcpRecoveryStore
	handle string
	lock   *os.File
	closed bool
}

var mcpRecoveryHandle = regexp.MustCompile(`^[0-9a-f]{48}$`)

func newMCPRecoveryStore(policy mcpPolicy) *mcpRecoveryStore {
	return &mcpRecoveryStore{directory: policy.recoveryDirectory, ttl: policy.recoveryTTL, maxAttempts: policy.recoveryMaxAttempts}
}

func (store *mcpRecoveryStore) prepare() error {
	if store == nil || store.directory == "" {
		return errors.New("recovery_corrupt: recovery directory is not configured")
	}
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		return errors.New("recovery_corrupt: recovery directory is unavailable")
	}
	info, err := os.Lstat(store.directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery_corrupt: recovery directory is unsafe")
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(store.directory, 0o700); err != nil {
			return errors.New("recovery_corrupt: recovery directory permissions are unsafe")
		}
	}
	resolved, err := filepath.EvalSymlinks(store.directory)
	if err != nil {
		return errors.New("recovery_corrupt: recovery directory must not contain symlinks")
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil || !os.SameFile(info, resolvedInfo) {
		return errors.New("recovery_corrupt: recovery directory is unsafe")
	}
	// macOS exposes /var as an alias of /private/var. The recovery directory
	// itself must not be a symlink, but trusted aliases in its ancestors are
	// safe once the target has been verified and retained canonically.
	store.directory = filepath.Clean(resolved)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("recovery_corrupt: recovery directory has an unsafe owner")
	}
	return nil
}

func (store *mcpRecoveryStore) create(record *mcpRecoveryRecord) (string, error) {
	if err := store.prepare(); err != nil {
		return "", err
	}
	for attempts := 0; attempts < 8; attempts++ {
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return "", errors.New("internal_error: generate recovery handle")
		}
		handle := hex.EncodeToString(random)
		wipe(random)
		record.Version = mcpRecoveryVersion
		record.ExpiresAt = time.Now().Add(store.ttl).UTC()
		if record.Attempt == 0 {
			record.Attempt = 1
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return "", errors.New("internal_error: encode recovery record")
		}
		encoded = append(encoded, '\n')
		err = writePrivate(store.recordPath(handle), encoded)
		wipe(encoded)
		if err == nil {
			return handle, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", errors.New("recovery_corrupt: recovery record could not be written")
		}
	}
	return "", errors.New("internal_error: allocate recovery handle")
}

func (store *mcpRecoveryStore) acquire(handle string) (*mcpRecoveryLease, *mcpRecoveryRecord, error) {
	if !mcpRecoveryHandle.MatchString(handle) {
		return nil, nil, errors.New("recovery_unknown: recovery handle is invalid")
	}
	lock, err := os.OpenFile(store.lockPath(handle), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, nil, errors.New("recovery_unknown: recovery operation is already active")
		}
		return nil, nil, errors.New("recovery_unknown: recovery handle is unavailable")
	}
	lease := &mcpRecoveryLease{store: store, handle: handle, lock: lock}
	record, err := store.read(handle)
	if err != nil {
		lease.release()
		return nil, nil, err
	}
	if time.Now().After(record.ExpiresAt) {
		if !isGeneratedMCPRecovery(record.Type) {
			_ = lease.delete()
		}
		lease.release()
		return nil, nil, errors.New("recovery_expired: recovery record has expired")
	}
	if record.Attempt >= store.maxAttempts {
		if !isGeneratedMCPRecovery(record.Type) {
			_ = lease.delete()
		}
		lease.release()
		return nil, nil, errors.New("recovery_exhausted: recovery attempt limit was reached")
	}
	return lease, record, nil
}

func isGeneratedMCPRecovery(recordType string) bool {
	return recordType == "generate_process" || recordType == "generate_env_file"
}

func (store *mcpRecoveryStore) read(handle string) (*mcpRecoveryRecord, error) {
	path := store.recordPath(handle)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("recovery_unknown: recovery record does not exist")
		}
		return nil, errors.New("recovery_corrupt: recovery record is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("recovery_corrupt: recovery record permissions are unsafe")
	}
	handleFile, err := os.Open(path)
	if err != nil {
		return nil, errors.New("recovery_corrupt: recovery record is unavailable")
	}
	defer handleFile.Close()
	decoder := json.NewDecoder(io.LimitReader(handleFile, 64*1024*1024))
	decoder.DisallowUnknownFields()
	var record mcpRecoveryRecord
	if err := decoder.Decode(&record); err != nil || record.Version != mcpRecoveryVersion || record.Type == "" {
		return nil, errors.New("recovery_corrupt: recovery record is invalid")
	}
	return &record, nil
}

func (lease *mcpRecoveryLease) save(record *mcpRecoveryRecord) error {
	record.Version = mcpRecoveryVersion
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("recovery_corrupt: recovery record could not be encoded")
	}
	encoded = append(encoded, '\n')
	defer wipe(encoded)
	temporary, err := os.CreateTemp(lease.store.directory, ".recovery-*")
	if err != nil {
		return errors.New("recovery_corrupt: recovery record could not be updated")
	}
	path := temporary.Name()
	complete := false
	defer func() {
		_ = temporary.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("recovery_corrupt: recovery record could not be updated")
	}
	if _, err := temporary.Write(encoded); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("recovery_corrupt: recovery record could not be updated")
	}
	if err := os.Rename(path, lease.store.recordPath(lease.handle)); err != nil {
		return errors.New("recovery_corrupt: recovery record could not be updated")
	}
	complete = true
	return nil
}

func (lease *mcpRecoveryLease) delete() error {
	path := lease.store.recordPath(lease.handle)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe recovery record")
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		zeros := make([]byte, minInt64(info.Size(), 1024*1024))
		remaining := info.Size()
		for remaining > 0 {
			chunk := int64(len(zeros))
			if chunk > remaining {
				chunk = remaining
			}
			_, _ = file.Write(zeros[:chunk])
			remaining -= chunk
		}
		_ = file.Sync()
		_ = file.Close()
	}
	return os.Remove(path)
}

func (lease *mcpRecoveryLease) release() {
	if lease == nil || lease.closed {
		return
	}
	lease.closed = true
	_ = lease.lock.Close()
	_ = os.Remove(lease.store.lockPath(lease.handle))
}

func (store *mcpRecoveryStore) discard(handle string) error {
	lease, _, err := store.acquireForCleanup(handle)
	if err != nil {
		return err
	}
	defer lease.release()
	return lease.delete()
}

func (store *mcpRecoveryStore) acquireForCleanup(handle string) (*mcpRecoveryLease, *mcpRecoveryRecord, error) {
	lock, err := os.OpenFile(store.lockPath(handle), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	lease := &mcpRecoveryLease{store: store, handle: handle, lock: lock}
	record, err := store.read(handle)
	if err != nil {
		return lease, nil, nil
	}
	return lease, record, nil
}

func (store *mcpRecoveryStore) recordPath(handle string) string {
	return filepath.Join(store.directory, handle+".json")
}

func (store *mcpRecoveryStore) lockPath(handle string) string {
	return filepath.Join(store.directory, handle+".lock")
}

func minInt64(left, right int64) int {
	if left < right {
		return int(left)
	}
	return int(right)
}

func (record *mcpRecoveryRecord) wipe() {
	wipe(record.Envelope)
	record.Secret = ""
	record.GeneratedSecret = ""
	record.PrivateLink = ""
	record.CreatorSecret = ""
	wipeStrings(record.Candidates)
}
