package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/sdk/go/wipeme"
)

type forgetRecoveryInput struct {
	RecoveryHandle string `json:"recovery_handle"`
}

func cleanupMCPRecovery(ctx context.Context, store *mcpRecoveryStore, settings config) {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		handle := strings.TrimSuffix(entry.Name(), ".json")
		if !mcpRecoveryHandle.MatchString(handle) {
			continue
		}
		lease, record, err := store.acquireForCleanup(handle)
		if err != nil {
			continue
		}
		if record == nil {
			_ = lease.delete()
			lease.release()
			continue
		}
		expired := time.Now().After(record.ExpiresAt) || record.Attempt >= store.maxAttempts
		if expired {
			if record.Type == "generate_process" {
				deleted, absent, deleteErr := deleteGeneratedRecoveryRemote(ctx, record, settings)
				if deleteErr == nil && (deleted || absent) {
					_ = lease.delete()
				}
			} else {
				_ = lease.delete()
			}
		}
		record.wipe()
		lease.release()
	}
}

type forgetRecoveryResult struct {
	Status               string `json:"status"`
	RemoteMessageDeleted bool   `json:"remote_message_deleted"`
	RecoveryDeleted      bool   `json:"recovery_deleted"`
}

func registerMCPForgetRecoveryTool(server *mcpsdk.Server, settings config, store *mcpRecoveryStore) {
	destructive, openWorld := true, true
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "forget_recovery",
		Title:       "Forget a pending recovery",
		Description: "Abandon a pending recovery. Unreleased generated messages are deleted remotely before local capability material is removed.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &destructive, IdempotentHint: true, OpenWorldHint: &openWorld},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input forgetRecoveryInput) (*mcpsdk.CallToolResult, forgetRecoveryResult, error) {
		if !mcpRecoveryHandle.MatchString(input.RecoveryHandle) {
			return nil, forgetRecoveryResult{}, errors.New("recovery_unknown: recovery handle is invalid")
		}
		lease, record, err := store.acquireForCleanup(input.RecoveryHandle)
		if err != nil {
			return nil, forgetRecoveryResult{}, errors.New("recovery_unknown: recovery operation is already active")
		}
		defer lease.release()
		if record == nil {
			if _, statErr := os.Lstat(store.recordPath(input.RecoveryHandle)); os.IsNotExist(statErr) {
				return nil, forgetRecoveryResult{Status: "already_absent", RecoveryDeleted: true}, nil
			}
			return nil, forgetRecoveryResult{}, errors.New("recovery_corrupt: recovery record is invalid")
		}
		defer record.wipe()
		if record.Type != "generate_process" {
			if err := lease.delete(); err != nil {
				return nil, forgetRecoveryResult{}, errors.New("recovery_corrupt: recovery record could not be removed")
			}
			return nil, forgetRecoveryResult{Status: "forgotten", RecoveryDeleted: true}, nil
		}
		deleted, _, err := deleteGeneratedRecoveryRemote(ctx, record, settings)
		if err != nil {
			return nil, forgetRecoveryResult{Status: "delete_pending", RecoveryDeleted: false}, nil
		}
		if err := lease.delete(); err != nil {
			return nil, forgetRecoveryResult{}, errors.New("recovery_corrupt: recovery record could not be removed")
		}
		return nil, forgetRecoveryResult{Status: "forgotten", RemoteMessageDeleted: deleted, RecoveryDeleted: true}, nil
	})
}

func deleteGeneratedRecoveryRemote(ctx context.Context, record *mcpRecoveryRecord, settings config) (bool, bool, error) {
	application := wipeme.ApplicationLink{MessageID: record.MessageID, Secret: record.Secret, CustomPassphrase: record.Manual}
	client, err := newAPIClient(settings.APIEndpoint)
	if err != nil {
		return false, false, err
	}
	for _, candidate := range record.Candidates {
		messageID, secret, deriveErr := mcpCandidateCryptoParameters(application, candidate)
		if deriveErr != nil {
			continue
		}
		deleted, deleteErr := deleteWithParametersContext(ctx, client, application.MessageID, messageID, secret)
		secret = ""
		if deleteErr == nil && deleted {
			return true, false, nil
		}
		if api, ok := wipeme.AsAPIError(deleteErr); ok {
			if api.StatusCode == 404 || api.StatusCode == 410 {
				return false, true, nil
			}
			if api.StatusCode == 401 || api.StatusCode == 403 {
				continue
			}
		}
		return false, false, deleteErr
	}
	return false, false, errors.New("generated message deletion was not authorized")
}
