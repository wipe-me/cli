package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wipe-me/sdk/go/wipeme"
)

type MCPLinkSource struct {
	PrivateLink string `json:"private_link,omitempty"`
	LinkFile    string `json:"link_file,omitempty"`
	LinkEnv     string `json:"link_env,omitempty"`
}

type deleteMessageInput struct {
	MCPLinkSource
	PassphraseSources []MCPPassphraseSource `json:"passphrase_sources,omitempty"`
	MissingIsSuccess  *bool                 `json:"missing_is_success,omitempty"`
}

type deleteMessageResult struct {
	Status    string `json:"status"`
	Deleted   bool   `json:"deleted"`
	MessageID string `json:"message_id"`
}

func registerMCPDeleteTool(server *mcpsdk.Server, policy mcpPolicy, settings config) {
	destructive, openWorld := true, true
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "delete_message",
		Title:       "Delete a private message",
		Description: "Permanently delete a Wipe.me message using its private capability without returning or logging the capability.",
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: &destructive,
			IdempotentHint:  true,
			OpenWorldHint:   &openWorld,
		},
	}, func(ctx context.Context, request *mcpsdk.CallToolRequest, input deleteMessageInput) (*mcpsdk.CallToolResult, deleteMessageResult, error) {
		privateLink, err := resolveMCPLinkValues(policy, input.PrivateLink, input.LinkFile, input.LinkEnv)
		if err != nil {
			return nil, deleteMessageResult{}, err
		}
		application, err := wipeme.ParseApplicationPrivateLink(privateLink)
		privateLink = ""
		if err != nil {
			return nil, deleteMessageResult{}, errors.New("invalid_link: private link is invalid")
		}
		candidates, err := mcpCredentialCandidates(application, input.PassphraseSources, policy)
		if err != nil {
			return nil, deleteMessageResult{}, err
		}
		defer wipeStrings(candidates)
		if len(candidates) == 0 {
			return nil, deleteMessageResult{}, errors.New("credential_unavailable: no passphrase source is available")
		}
		client, err := newAPIClient(settings.APIEndpoint)
		if err != nil {
			return nil, deleteMessageResult{}, errors.New("deletion_failed: service configuration is invalid")
		}
		missingIsSuccess := true
		if input.MissingIsSuccess != nil {
			missingIsSuccess = *input.MissingIsSuccess
		}
		credentialRejected := false
		for _, candidate := range candidates {
			messageID, secret, deriveErr := mcpCandidateCryptoParameters(application, candidate)
			if deriveErr != nil {
				continue
			}
			deleted, deleteErr := deleteWithParametersContext(ctx, client, application.MessageID, messageID, secret)
			secret = ""
			if deleteErr == nil && deleted {
				return nil, deleteMessageResult{Status: "deleted", Deleted: true, MessageID: application.MessageID}, nil
			}
			if api, ok := wipeme.AsAPIError(deleteErr); ok {
				switch api.StatusCode {
				case 401, 403:
					credentialRejected = true
					continue
				case 404, 410:
					if missingIsSuccess {
						return nil, deleteMessageResult{Status: "already_absent", Deleted: false, MessageID: application.MessageID}, nil
					}
					return nil, deleteMessageResult{}, errors.New("message_unavailable: message is already absent")
				}
			}
			return nil, deleteMessageResult{}, errors.New("deletion_failed: service request failed")
		}
		if credentialRejected {
			return nil, deleteMessageResult{}, errors.New("credential_rejected: available credentials did not authorize deletion")
		}
		return nil, deleteMessageResult{}, errors.New("deletion_failed: message was not deleted")
	})
}

func mcpCredentialCandidates(application wipeme.ApplicationLink, sources []MCPPassphraseSource, policy mcpPolicy) ([]string, error) {
	if len(sources) > 8 {
		return nil, errors.New("invalid_arguments: at most eight passphrase sources are allowed")
	}
	candidates := []string{}
	if !application.CustomPassphrase {
		candidates = append(candidates, application.Secret)
	}
	for _, source := range sources {
		count := 0
		if source.PassphraseFile != "" {
			count++
		}
		if source.PassphraseEnv != "" {
			count++
		}
		if count != 1 {
			wipeStrings(candidates)
			return nil, errors.New("credential_source_conflict: each passphrase source must select exactly one source")
		}
		value := ""
		if source.PassphraseFile != "" {
			path, err := policy.validateReadFile(source.PassphraseFile)
			if err != nil {
				wipeStrings(candidates)
				return nil, fmt.Errorf("%w: passphrase file is unavailable", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				wipeStrings(candidates)
				return nil, errors.New("credential_unavailable: passphrase file is unavailable")
			}
			value = trimLine(string(data))
			wipe(data)
		} else {
			if !mcpEnvironmentAllowed(policy, policy.allowedPassphraseEnv, source.PassphraseEnv) {
				wipeStrings(candidates)
				return nil, errors.New("credential_source_conflict: passphrase environment source is not allowed")
			}
			var ok bool
			value, ok = os.LookupEnv(source.PassphraseEnv)
			if !ok {
				wipeStrings(candidates)
				return nil, errors.New("credential_unavailable: passphrase environment source is unavailable")
			}
		}
		if value == "" {
			wipeStrings(candidates)
			return nil, errors.New("credential_unavailable: passphrase source is empty")
		}
		candidates = append(candidates, value)
	}
	seen := map[string]struct{}{}
	unique := candidates[:0]
	for _, candidate := range candidates {
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		unique = append(unique, candidate)
	}
	return unique, nil
}

func mcpCandidateCryptoParameters(application wipeme.ApplicationLink, candidate string) (string, string, error) {
	if application.CustomPassphrase {
		return wipeme.DeriveCustomCryptoParameters(candidate, application.MessageID)
	}
	copy := application
	copy.Secret = candidate
	return copy.EnvelopeCryptoParameters()
}

func deleteWithParametersContext(ctx context.Context, client *wipeme.Client, publicID, messageID, secret string) (bool, error) {
	key, err := wipeme.DeriveDeletionKey(messageID, secret)
	if err != nil {
		return false, err
	}
	defer wipe(key[:])
	result, err := client.DeleteMessage(ctx, publicID, wipeme.DeletionKeyHeader(key))
	if err != nil {
		return false, err
	}
	return result.Deleted, nil
}
