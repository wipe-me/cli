# Wipe.me CLI MCP server v1

Status: final implementation specification
Target release: `v0.3.0-alpha.1`
Command: `wipeme mcp`

## 1. Purpose

`wipeme mcp` exposes a deliberately agent-oriented subset of the
Wipe.me CLI through Model Context Protocol tools. It reuses the existing Go SDK,
encrypted envelope v1, compact link formats, metadata cleanup, configuration
resolution, and API client. It must not introduce another cryptographic or message
format.

The MCP surface is designed to let an agent create and apply secrets without
receiving plaintext. It intentionally has no tool that returns decrypted message
text, attachment data, generated passwords, environment values, or process output.

The existing human CLI remains compatible and unchanged:

```text
wipeme [options] [file ...]
wipeme read [options] <private-link>
wipeme exec [options] <private-link> -- <command> [args...]
wipeme delete [options] [link]
```

### 1.1 Preferred execution workflow

For commands that may require validation, retries, restarts, or repeated runs,
prefer `consume_into_env_file` over `consume_into_process_env`:

1. Consume the remote message exactly once into a mode-`0600` environment file.
2. Let the agent or operator run one or more commands using that file without
   another Wipe.me retrieval and without asking for the secret again.
3. Keep the file out of source control and delete it when the workflow is complete.

This separates destructive one-time retrieval from fallible process execution and
avoids a retry loop where every failed run would otherwise need another message.
It deliberately creates a reusable local secret, so filesystem permissions and
cleanup become the operator's responsibility. Direct process tools remain useful
for a deliberate single execution when no persistent plaintext file is acceptable.

Docker is the recommended execution boundary for agent-run applications because it
provides a reproducible command and explicit filesystem/process scope. It is not a
secret vault: users with Docker daemon access can inspect container environments.
Use `--rm`, limit daemon access, and remove the environment file after its required
reuse window.

### 1.2 Explicit non-goals

- No `create_message` tool accepts literal message text. Model-supplied text is
  already visible to the model and MCP transcript.
- No tool claims to modify the already-running MCP host or agent environment. An
  MCP server process cannot modify its parent's environment. Environment-file
  tools write only an explicit private destination; process tools inject secrets
  only into approved child processes.
- No general-purpose plaintext session, environment handle, arbitrary command
  executor, shell export returned through MCP, clipboard mutation or direct-read
  tool is exposed.
- No streamable HTTP transport is included in v1. Local filesystem and process
  capabilities remain local to the stdio server.
- No stdin attachment or passphrase source is exposed because stdin is the MCP
  transport.

## 2. Protocol and transport

- Implement the server with the official Go MCP SDK and pin an exact release.
- Initially support local stdio transport only.
- While `wipeme mcp` is running, that process's stdin and stdout belong
  exclusively to MCP JSON-RPC framing. This does not change the ordinary CLI:
  `wipeme` may still read message content from stdin, print links to stdout, and
  `wipeme exec` may still connect a child to the user's terminal streams.
- Logs and diagnostics go to stderr and must be secret-safe.
- Child processes must never inherit MCP stdin or stdout.
- Advertise tools only. Do not expose decrypted resources, prompts, or sampling.
- Return typed `structuredContent` conforming to an `outputSchema` and also a
  concise serialized JSON text block for compatibility.
- Use MCP progress notifications for SDK encryption and upload progress when the
  client negotiated support. Never print the CLI progress bar in MCP mode.
- Publish short server instructions. Their first 512 characters must state that
  tools consume one-time messages, never return plaintext, and that process tools
  execute only administrator-approved profiles.

For Codex, local installation is:

```sh
codex mcp add wipeme -- wipeme mcp
```

The command help is intentionally small:

```text
Usage: wipeme mcp [options]

Run the agent-safe Wipe.me MCP server over stdio.

Options:
  -access string
        access policy: host or restricted (default host)
  -config string
        configuration file
  -version
        print the version and exit before starting MCP
```

The MCP server remains the plaintext-isolation boundary. Filesystem and environment
authorization defaults to the local host's OS permissions and approval model;
`restricted` mode adds server-side allowlists. An optional skill or plugin may
describe workflows and declare the MCP dependency, but instructions must not be
relied upon to prevent unsafe behavior.

## 3. Security invariants

These requirements are mandatory and are not agent-configurable:

1. No direct-read or plaintext-returning tool is registered.
2. Raw secret values and literal passphrases are not accepted in tool arguments.
3. Private-link fragments, passphrases, generated secrets, decrypted blocks,
   attachment contents, and process output never appear in logs or errors.
4. Creation endpoint URLs are resolved from trusted CLI configuration, never from
   tool arguments.
5. Host access accepts absolute paths permitted by the OS. Restricted access also
   requires paths to remain inside configured read and write roots.
6. Secret output files use mode `0600`; private directories use mode `0700`.
7. Outputs default to no-overwrite. Only environment-file tools accept explicit
   overwrite, and they may atomically replace only a regular non-symlink file.
8. Process execution uses configured profiles and `exec` directly, never a shell.
9. Successful process execution always wipes recovery state.
10. Successful file and environment-file materialization always wipes recovery
    state.
11. Failed deletion of a generated pending message retains recovery state so that
    deletion can be retried.
12. Manual passphrases may come only from a protected file or environment source
    permitted by the active access policy.
13. Automatic-key fragments never leave the client in an HTTP request.
14. Supported attachment metadata is always stripped using the existing CLI
    implementation. There is no MCP option to disable privacy cleanup.
15. Limits and link constants come from the SDK/backend contract rather than new
    duplicated constants.

An MCP host may display or log tool arguments and results. Direct private-link
arguments and returned links are bearer capabilities and must be treated as such.

## 4. Common input types

### 4.1 Link source

Exactly one source is required:

```ts
type LinkSource =
  | { private_link: string }
  | { link_file: string }
  | { link_env: string };
```

`link_file` is recommended for agents. A file has one trailing `LF` or `CRLF`
removed; other whitespace is preserved. In host mode, `link_env` may name any
valid environment variable inherited by the MCP process. Restricted mode requires
it in `allowed_link_env`. Empty, ambiguous, or malformed sources fail before
network access.

### 4.2 Passphrase source

One passphrase source is:

```ts
type PassphraseSource =
  | { passphrase_file: string }
  | { passphrase_env: string };
```

There is no `passphrase` string, passphrase stdin, or terminal prompt in MCP mode.
Automatic links use their fragment locally. Passphrase files have one trailing
line ending removed without trimming ordinary spaces. Host mode relies on OS file
access and inherited environment; restricted mode additionally enforces the
configured read roots and `allowed_passphrase_env`.

Creation accepts at most one source because that value defines the manual
capability. Consumption and deletion accept an ordered `passphrase_sources` array,
limited to eight entries. They try the automatic fragment first, followed by each
file/environment source in request order, deduplicate byte-identical candidates,
retrieve the envelope at most once, and use authenticated decryption rather than
plaintext plausibility to select a candidate. To use the conventional environment
variable, pass `{ "passphrase_env": "WIPEME_PASSPHRASE" }` explicitly.

### 4.3 Creation controls

```ts
interface CreationControls {
  expires_in_seconds?: number;
  passphrase_source?: PassphraseSource;
  include_qr?: boolean;       // default false
  receipt_file?: string;
  link_file?: string;
}
```

- Expiry defaults to resolved CLI configuration and must satisfy service limits.
- A passphrase source selects manual mode. Manual links contain no passphrase.
- `receipt_file` and `link_file` are optional mode-`0600`, no-overwrite outputs.
- Successful creation always returns the private link in structured content, even
  when a link file or receipt was requested.

### 4.4 QR result

`include_qr: true` adds one standard MCP image content block:

```json
{
  "type": "image",
  "mimeType": "image/png",
  "data": "<base64 PNG>",
  "annotations": { "audience": ["user"], "priority": 1 }
}
```

The QR is returned inline through MCP; it is not written to a file and no QR
file path is included in `CreationResult`. `qr_included: true` guarantees that
the response also contains the image content block described above.

The PNG contains the exact returned private link. It is always normal
black-on-white with a four-module quiet zone, fixed error correction suitable for
screenshots, no ancillary metadata, and deterministic dimensions. MCP mode has no
inverse, JPEG, ANSI, Unicode, or text QR option. Tests must decode the generated
PNG with an independent decoder and compare the recovered link byte-for-byte.

The image is a bearer capability equivalent to the private link. Content
annotations are advisory and do not replace access control.

### 4.5 Common creation result

```ts
interface CreationResult {
  status: "created" | "creation_uncertain";
  private_link: string;
  message_id: string;
  expires_at: string;          // RFC 3339
  attachment_count: number;
  qr_included: boolean;
  receipt_written: boolean;
  link_file_written: boolean;
}
```

Plaintext sizes are omitted from results. On an ambiguous API result, do not
silently create a second message with a new ID. Return a sanitized
`creation_uncertain` result only when the SDK can safely provide the original
capability; otherwise return a stable error.

## 5. Process profiles

Agents never provide executable paths or shell command strings. They select an
administrator-defined profile:

```yaml
mcp:
  process_profiles:
    database-migrate:
      role: consumer
      executable: /usr/local/bin/database-tool
      fixed_args: [migrate]
      argument_patterns:
        - '^[A-Za-z0-9._/-]+$'
      max_arguments: 4
      timeout: 2m
      accepted_exit_codes: [0]
      allowed_secret_env: [DATABASE_PASSWORD]
      inherit_env: [HOME, PATH]
      max_stdout_bytes: 65536
```

Profile rules:

- Executable paths are absolute, regular files and are checked before retrieval.
- Every profile has exactly one role: `producer` or `consumer`. Tools reject a
  profile with the wrong role.
- Profiles define fixed arguments, permitted dynamic arguments, environment
  inheritance, working directory, timeout, output limit and accepted exit codes.
- Agent arguments are passed as an argv array after validation.
- `sh`, `bash -c`, arbitrary interpreters, `env`, `printenv`, network exfiltration
  tools and equivalent escape profiles must not be shipped as defaults.
- Consumer process stdout and stderr are discarded by default. A future profile
  output policy must never return output through MCP without a separate security
  review.
- Producer stderr is discarded. Producer stdout is secret input and is never
  returned.

## 6. Recovery model

The server deletes the remote copy when retrieval begins. Reliable retries
therefore require local state. A destructive read and completely stateless retry
cannot both be guaranteed.

Before decrypting or writing output, the MCP server persists a recovery record in
its private recovery directory. Records use opaque cryptographically random handles,
mode `0600`, bounded TTLs and bounded attempts. The directory uses mode `0700`.

Recovery records may contain the encrypted envelope and the minimum capability
material needed to resume the original operation. They are sensitive creator
receipts and must never be returned by path, logged, or exposed as MCP resources.
Use an operating-system secret store when available; mode-`0600` local records are
the portable container fallback.

Defaults:

```yaml
mcp:
  recovery_directory: ~/.local/state/wipeme/mcp-recovery
  recovery_ttl: 15m
  recovery_max_attempts: 5
```

A recovery handle is scoped to the local OS user and original operation type. It
cannot change to a different process profile. Validated process arguments, block
mappings, environment-file destination, format, and overwrite choice may change on
retry. Expired, corrupted, exhausted and successful records are wiped. Cleanup runs
at startup, periodically, and at normal shutdown.

## 7. Tool: `inspect_private_link`

Validates a link locally without network access.

```ts
type InspectPrivateLinkInput = LinkSource;

interface InspectPrivateLinkResult {
  valid: boolean;
  reason_code?: "invalid_url" | "invalid_message_id" | "invalid_fragment";
  message_id?: string;
  mode?: "automatic" | "manual";
  has_fragment_secret?: boolean;
  requires_external_passphrase?: boolean;
}
```

The result never echoes or normalizes the complete private link and never reports
remote existence. Annotation: read-only, non-destructive, closed-world.

## 8. Tool: `generate_secret`

Generates a password internally, creates an ordinary Wipe.me message whose first
block contains it, and returns only the link.

```ts
interface GenerateSecretInput extends CreationControls {
  length?: number;                    // default 32
  chars?: "portable" | "alnum" | "base58" | "base64url" |
          "hex" | "digits" | "letters" | "ascii";
  alphabet?: string;
  no_require_each?: boolean;          // default false
  attachment_paths?: string[];
}
```

- `chars` defaults to `portable`.
- `chars` and `alphabet` are mutually exclusive.
- Custom alphabet validation and class requirements exactly match the existing CLI.
- Password length constraints and unbiased generation reuse `internal/password`.
- The generated password is never included in tool content, structured output,
  logs, errors, receipts visible through MCP, or QR data except as encrypted message
  content behind the link.
- Attachments remain supported as later blocks and receive metadata cleanup.

Result: `CreationResult`. Annotation: mutating, non-idempotent, open-world.

## 9. Tool: `generate_secret_into_process_env`

Generates one password, uploads it, injects the same password into an approved
consumer process and releases the link only after an accepted exit code.

```ts
interface GenerateSecretIntoProcessEnvInput extends CreationControls {
  length?: number;
  chars?: GenerateSecretInput["chars"];
  alphabet?: string;
  no_require_each?: boolean;
  profile: string;
  arguments?: string[];
  environment_name: string;
}
```

Execution flow:

1. Validate every local option and process profile.
2. Generate the password once.
3. Encrypt and upload the message.
4. Persist recovery before starting the child.
5. Inject the exact generated password into the profile-approved environment name.
6. Start the process directly with no inherited MCP streams.
7. On an accepted exit code, return the link and optional QR, then mandatorily wipe
   recovery state.
8. On launch failure, timeout, signal or non-accepted exit, return only a recovery
   handle. Do not return the private link or QR.
9. Retries reuse the same password. Never generate a new password automatically.

```ts
interface PendingGeneratedExecutionResult {
  status: "execution_failed" | "launch_failed" | "timed_out" | "signaled";
  remote_message_created: true;
  started: boolean;
  exit_code?: number;
  signal?: string;
  retryable: true;
  recovery_handle: string;
  retry_until: string;
  attempt: number;
}
```

Successful initial execution or retry returns:

```ts
interface GeneratedExecutionSuccess {
  status: "executed";
  private_link: string;
  message_id: string;
  expires_at: string;
  exit_code: number;
  attempt: number;
  qr_included: boolean;
  receipt_written: boolean;
  link_file_written: boolean;
  recovery_deleted: true;
}
```

The generated remote message remains hidden until execution succeeds. Abandoning
this recovery type must delete the remote message before wiping local capability
material.

## 10. Tool: `create_from_files`

Creates one message from an optional message file and zero or more attachments.

```ts
interface CreateFromFilesInput extends CreationControls {
  message_file?: string;
  message_format?: "text" | "editorjs_json";  // default text
  attachment_paths?: string[];
}
```

At least one input file is required. `message_file` content never enters MCP
arguments or results. `editorjs_json` must parse as the existing document model;
attachments are appended without rewriting unrelated blocks.

Paths must be absolute, regular files and stable while read. Restricted mode also
requires them inside allowed read roots. Reject devices, sockets, FIFOs, directory
inputs, root escapes and unsafe symlinks. Preserve attachment ordering. Result:
`CreationResult`.

## 11. Tool: `create_from_env`

Creates a message from one or more server environment variables permitted by the
active access policy.

```ts
interface CreateFromEnvInput extends CreationControls {
  variables: Array<{ source: string }>;
}
```

- Host mode accepts valid names inherited by the MCP process. Restricted mode
  requires names in `mcp.allowed_source_env`.
- Each value becomes an ordinary text block in request order.
- v1 deliberately has no label option. The current document model has no labelled
  secret block, and inserting a text label would break first-text-block selection.
- Missing or explicitly empty values fail atomically before upload.
- Limit the number of variables; default maximum is 16.
- Values are removed from any subsequently launched child environment.

Result: `CreationResult`.

## 12. Tool: `create_from_process_output`

Runs an approved producer profile and encrypts its stdout without exposing it.

```ts
interface CreateFromProcessOutputInput extends CreationControls {
  profile: string;
  arguments?: string[];
  stdin_file?: string;
  output:
    | { mode: "text" }
    | { mode: "attachment"; filename: string; mime_type?: string };
  attachment_paths?: string[];
}
```

- Validate the complete profile, argv, stdin file and attachments before execution.
- Capture stdout up to the profile maximum. Exceeding the limit kills the producer
  and uploads nothing.
- A non-accepted producer exit uploads nothing.
- Never capture producer stderr into the message or return it.
- In attachment mode, validate filename and MIME type and treat captured bytes as
  the first attachment. Additional attachments follow in request order.
- In text mode, stdout becomes the message body without trimming.

Result: `CreationResult`.

## 13. Tool: `consume_into_files`

Consumes and decrypts a message into a newly created private directory without
returning plaintext.

```ts
type ConsumeIntoFilesInput = LinkSource & {
  passphrase_sources?: PassphraseSource[];
  destination_directory: string;
  message_format?: "text" | "editorjs_json";  // default text
  block?: number;                              // optional document block index
  write_message?: boolean;                     // default true
  write_attachments?: boolean;                 // default true
}
```

- Validate the link source, credential source and destination before retrieval.
- The destination must be inside an allowed write root and must not exist.
- Retrieve once, persist recovery, try authenticated decryption locally, stage all
  outputs in a mode-`0700` temporary directory, then atomically rename it.
- Message and attachment files use mode `0600`.
- Attachment filenames use the existing traversal-safe basename behavior and must
  additionally resolve duplicate/colliding names deterministically with ordinal
  prefixes before finalization.
- `block` is a zero-based document block index, matching current CLI semantics; the
  selected block must be text-compatible. Without `block`, text mode writes the
  first compatible text-bearing block in document order.
- `editorjs_json` writes the decrypted document to a file; it is never returned.
- No original attachment filenames or decrypted metadata appear in the MCP result.
- If no compatible text exists and `block` was omitted, attachments may still be
  written and `message_written` is false. An explicit incompatible `block` fails.
- Reject requests where both `write_message` and `write_attachments` are false.
- Create the temporary staging directory beside the final destination so the final
  rename stays on the same filesystem.

```ts
interface ConsumeIntoFilesResult {
  status: "consumed";
  message_written: boolean;
  attachment_count: number;
  destination_directory: string;
  recovery_deleted: true;
}
```

On staging, disk, rename or output failure, retain recovery and return a handle for
`retry_into_files`.

```ts
interface PendingFileConsumptionResult {
  status: "output_failed";
  consumed: true;
  retryable: true;
  recovery_handle: string;
  retry_until: string;
  attempt: number;
}
```

## 14. Tool: `retry_into_files`

Retries materialization from a file-consumption recovery record without another
server request.

```ts
interface RetryIntoFilesInput {
  recovery_handle: string;
  destination_directory: string;
  message_format?: "text" | "editorjs_json";
  block?: number;
  write_message?: boolean;
  write_attachments?: boolean;
}
```

The operation type cannot change. A new destination is allowed after full local
validation. Success mandatorily wipes recovery. Failure increments the attempt
counter and retains recovery until its limit or TTL. Success returns
`ConsumeIntoFilesResult`; another failure returns
`PendingFileConsumptionResult`.

## 15. Tool: `consume_into_env_file`

Consumes a message and writes selected compatible text blocks to an explicit
private environment file without returning their values.

```ts
type EnvironmentFileFormat = "dotenv" | "docker" | "shell" | "systemd";

type ConsumeIntoEnvFileInput = LinkSource & {
  passphrase_sources?: PassphraseSource[];
  destination_file: string;
  environment: Array<{
    name: string;
    block?: number;                // omitted: first compatible text block
  }>;
  format?: EnvironmentFileFormat; // default dotenv
  overwrite?: boolean;            // default false
}
```

- The destination and all mappings are validated before retrieval.
- Names must be valid environment names, must be unique, and must not start with
  `WIPEME_`. Environment-file mappings do not require a process profile.
- `overwrite: false` refuses an existing destination. `overwrite: true` may
  replace only a regular, non-symlink destination.
- Output is staged beside the destination, synchronized, and installed atomically
  with mode `0600`. No-overwrite installation does not clobber a file created by
  a concurrent process.
- The four encoders are deliberately separate:
  - `dotenv` writes double-quoted assignments and escapes backslash, double quote,
    dollar, newline, carriage return, and tab for conventional dotenv readers.
  - `docker` writes raw `NAME=value` lines compatible with
    `docker run --env-file`; CR, LF, and NUL are refused because Docker's format
    cannot represent them faithfully.
  - `shell` writes POSIX-sourceable `export NAME='value'` assignments with safe
    single-quote handling and supports multiline values.
  - `systemd` writes UTF-8 double-quoted assignments following the
    `EnvironmentFile=` grammar and supports multiline values.
- All encoders reject NUL. The result never contains an encoded line or value.

### 15.1 Host-command example

The following arguments map text blocks to names while keeping values out of MCP:

```json
{
  "link_file": "/workspace/private/message.link",
  "destination_file": "/workspace/private/application.env",
  "environment": [
    { "name": "DATABASE_PASSWORD", "block": 0 },
    { "name": "API_TOKEN", "block": 1 }
  ],
  "format": "shell",
  "overwrite": false
}
```

The tool privately materializes assignments equivalent to:

```sh
export DATABASE_PASSWORD='[decrypted block 0]'
export API_TOKEN='[decrypted block 1]'
```

The agent can inject the entire file into a child command without reading it:

```sh
sh -c '. /workspace/private/application.env && exec ./bin/migrate'
```

The shell and child can access the plaintext by design; MCP results cannot.

### 15.2 Docker and Compose example

For a Docker consumer, request the Docker encoder explicitly:

```json
{
  "link_file": "/workspace/private/docker-message.link",
  "destination_file": "/workspace/private/container.env",
  "environment": [
    { "name": "DATABASE_PASSWORD", "block": 0 },
    { "name": "API_TOKEN", "block": 1 }
  ],
  "format": "docker",
  "overwrite": false
}
```

```sh
docker run --rm --env-file /workspace/private/container.env example/app migrate
docker run --rm --env-file /workspace/private/container.env example/app verify
```

Both commands reuse the single consumed local file. For Compose 2.30 or newer:

```yaml
services:
  app:
    image: example/app
    env_file:
      - path: /workspace/private/container.env
        format: raw
```

The file is intentionally reusable across `docker run` invocations or Compose
restarts until the operator deletes it.

```ts
interface EnvironmentFileResult {
  status: "written" | "output_failed";
  consumed?: boolean;
  remote_message_created?: boolean;
  destination_file?: string;
  format?: EnvironmentFileFormat;
  variables_written?: number;
  attempt: number;
  retryable: boolean;
  recovery_handle?: string;
  retry_until?: string;
  recovery_deleted: boolean;
  private_link?: string;          // successful generated-secret operation only
  message_id?: string;
  expires_at?: string;
  qr_included?: boolean;
  receipt_written?: boolean;
  link_file_written?: boolean;
}
```

An output or encoding failure after retrieval returns `output_failed` and a
recovery handle. It never performs another retrieval automatically.

## 16. Tool: `retry_into_env_file`

Retries either a consumed-message or generated-secret environment-file operation
from protected local recovery.

```ts
interface RetryIntoEnvFileInput {
  recovery_handle: string;
  destination_file?: string;
  environment?: Array<{ name: string; block?: number }>;
  format?: EnvironmentFileFormat;
  overwrite?: boolean;
  include_qr?: boolean;           // generated-secret recovery only
}
```

Omitted fields reuse the validated original settings. Revised fields receive full
validation. Consumed-message retries decrypt the retained envelope and make no
second GET. Generated-secret retries reuse the exact original generated value and
make no second upload. A successful generated retry releases its previously hidden
private link and optional inline PNG QR; consumed-message retries never return a
link or QR.

## 17. Tool: `generate_secret_into_env_file`

Generates one password, uploads it, writes that exact value to an environment file,
and releases the private link only after file installation succeeds.

```ts
interface GenerateSecretIntoEnvFileInput extends CreationControls {
  length?: number;
  chars?: GenerateSecretInput["chars"];
  alphabet?: string;
  no_require_each?: boolean;
  destination_file: string;
  environment: Array<{ name: string; block?: 0 }>;
  format?: EnvironmentFileFormat; // default dotenv
  overwrite?: boolean;            // default false
}
```

The generated message contains one text block, so mappings may omit `block` or use
only block `0`. Multiple names may intentionally receive the same generated value.
On output failure, the link and QR remain hidden behind recovery. Successful retry
reuses the same secret; abandonment, expiration, or exhausted retries delete the
unreleased remote message before wiping local recovery whenever the service is
reachable.

## 18. Tool: `consume_into_process_env`

Consumes a message and injects selected compatible text blocks into an approved
consumer process.

This is the single-execution path. Prefer `consume_into_env_file` when a command
may need retries, validation runs, restarts, Docker/Compose, or multiple invocations.

```ts
type ConsumeIntoProcessEnvInput = LinkSource & {
  passphrase_sources?: PassphraseSource[];
  profile: string;
  arguments?: string[];
  environment: Array<{
    name: string;
    block?: number;       // omitted means first compatible text block
  }>;
}
```

- `environment` is repeatable, matching CLI `--set-env` selectors.
- Names must be valid, profile-allowlisted and must not start with `WIPEME_`.
- Validate all arguments, mappings, executable and working directory before
  retrieval.
- Retrieve once, persist recovery, decrypt locally, select blocks in document order
  and inject exact values.
- Start from the profile's minimal inherited environment. Remove Wipe.me link and
  passphrase source variables.
- Child stdin is null unless a fixed profile defines a safe source. stdout and
  stderr are discarded.
- On an accepted exit code, mandatorily wipe recovery.
- On launch failure, timeout, signal or non-accepted exit, retain recovery and
  return a retry handle.

```ts
interface ProcessExecutionResult {
  status: "executed" | "execution_failed" | "launch_failed" |
          "timed_out" | "signaled";
  consumed: true;
  started: boolean;
  exit_code?: number;
  signal?: string;
  attempt: number;
  retryable: boolean;
  recovery_handle?: string;
  retry_until?: string;
  recovery_deleted: boolean;
}
```

## 19. Tool: `retry_process_env`

Retries either a consumed-message or generated-secret process operation.

Process retry exists to recover a single intended operation without consuming or
generating again. It should not be used as a general execution loop; materialize a
private environment file when the secret must survive multiple runs.

```ts
interface RetryProcessEnvInput {
  recovery_handle: string;
  arguments?: string[];
  environment?: Array<{ name: string; block?: number }>; // consumed-message only
  environment_name?: string;                             // generated-secret only
  include_qr?: boolean;
}
```

- The original profile and operation type are immutable.
- Revised argv and block mappings must still satisfy that profile.
- Block values remain zero-based document block indexes, not indexes among only
  text-bearing blocks.
- No server retrieval or new secret generation occurs.
- On accepted exit, recovery is mandatorily wiped.
- For a generated-secret operation, the successful retry releases its previously
  hidden private link and optional QR.
- For consumed-message operations, no link or QR is returned.

## 20. Tool: `forget_recovery`

Explicitly abandons a pending recovery operation.

```ts
interface ForgetRecoveryInput {
  recovery_handle: string;
}

interface ForgetRecoveryResult {
  status: "forgotten" | "delete_pending" | "already_absent";
  remote_message_deleted: boolean;
  recovery_deleted: boolean;
}
```

For consumed-message and file-output records, wipe local recovery immediately. For
generated-secret records whose private link has not been released, first delete the
remote message using the retained deletion capability. If deletion fails
transiently, retain the record and return `delete_pending`.

## 21. Tool: `delete_message`

Deletes a message using its automatic fragment or separately sourced manual
passphrase.

```ts
type DeleteMessageInput = LinkSource & {
  passphrase_sources?: PassphraseSource[];
  missing_is_success?: boolean;      // default true
}

interface DeleteMessageResult {
  status: "deleted" | "already_absent";
  deleted: boolean;
  message_id: string;
}
```

There is no `confirm` argument. Mark the tool destructive and let the MCP host apply
human approval. Deletion is effectively idempotent and safe to retry. Never return
or log the deletion capability.

## 22. MCP-only omissions from current CLI help

The following current CLI features are deliberately absent or transformed:

| Current CLI behavior | MCP behavior |
|---|---|
| Message plaintext from stdin or `--message` | Omitted; stdin is MCP transport and literal text would already be model-visible |
| `read` to stdout and `read --json` | Omitted; only file materialization is exposed |
| `--passphrase-stdin` and prompt | Omitted; MCP is non-interactive |
| Arbitrary `exec -- command` | Replaced by process profiles |
| Child stdin/stdout/stderr inheritance | Omitted because MCP owns protocol streams and plaintext must not leak |
| `--copy` | Omitted; server processes must not mutate a desktop clipboard |
| Terminal `--qr` / `--qr-big` / `--qr-invert` | Replaced by optional normal inline PNG only |
| Per-call `--api-url`, `--site-url`, `--server-url` | Omitted to prevent secret redirection; trusted config only |
| Human progress bar | Replaced by MCP progress notifications |
| Child exit code as server process exit | Returned as structured tool data |
| Direct creator receipt on stdout | Omitted; optional private receipt file only |

Current password controls (`length`, `chars`, `alphabet`, `no_require_each`), expiry,
manual mode, repeated attachments, block selectors, link sources, passphrase file or
environment sources, link files, receipts, metadata cleanup and stable sanitized
failure categories are retained where safe.

## 23. Tool annotations and approval guidance

| Tool | Read-only | Destructive | Idempotent | Open-world |
|---|---:|---:|---:|---:|
| `inspect_private_link` | yes | no | yes | no |
| `generate_secret` | no | no | no | yes |
| `generate_secret_into_process_env` | no | yes | no | yes |
| `create_from_files` | no | no | no | yes |
| `create_from_env` | no | no | no | yes |
| `create_from_process_output` | no | yes | no | yes |
| `consume_into_files` | no | yes | no | yes |
| `retry_into_files` | no | yes | no | no |
| `consume_into_env_file` | no | yes | no | yes |
| `retry_into_env_file` | no | yes | no | no |
| `generate_secret_into_env_file` | no | yes | no | yes |
| `consume_into_process_env` | no | yes | no | yes |
| `retry_process_env` | no | yes | no | profile-dependent |
| `forget_recovery` | no | yes | yes | generated records may contact server |
| `delete_message` | no | yes | yes | yes |

Annotations are advisory. The server must enforce every safety property itself.
Recommended host policy is prompt approval for all tools except
`inspect_private_link`.

## 24. Errors

All tool failures use stable codes and sanitized messages. Expected operation
outcomes such as a child exit, retryable file error or already-absent deletion are
successful MCP calls with structured status values, not protocol errors.

Stable error codes:

```text
invalid_arguments
invalid_link
link_source_conflict
credential_source_conflict
credential_unavailable
credential_rejected
retrieval_failed
message_unavailable
output_refused
path_outside_allowed_root
profile_unknown
profile_argument_rejected
profile_unavailable
producer_failed
output_limit_exceeded
recovery_unknown
recovery_expired
recovery_exhausted
recovery_corrupt
creation_failed
deletion_failed
internal_error
```

Errors never include tool argument dumps, private links, fragments, passphrases,
environment values, decrypted metadata, ciphertext details, producer output or raw
API bodies.

## 25. Configuration

Existing precedence remains flags, environment, user YAML, system YAML and built-in
defaults. MCP has no per-call endpoint override. Extend YAML with a strict `mcp`
mapping and reject unknown fields:

`host` is the default for local stdio clients. It relies on the OS account,
container or sandbox, desktop-host permissions, and MCP approval flow for
filesystem and inherited-environment authorization:

```yaml
server_url: https://wipe.me
expires: 24h

mcp:
  access_mode: host
  recovery_directory: /run/user/1000/wipeme-mcp-recovery
  recovery_ttl: 15m
  recovery_max_attempts: 5
  max_environment_sources: 16
  process_profiles: {}
```

Host mode still requires absolute paths, regular input files, existing output
parents, no-overwrite destinations, safe attachment names, private permissions,
and protected recovery. It does not turn process tools into arbitrary command
execution: producer and consumer process profiles remain mandatory.

`restricted` adds Wipe.me-managed filesystem and environment allowlists:

```yaml
server_url: https://wipe.me
expires: 24h

mcp:
  access_mode: restricted
  allowed_read_roots:
    - /workspace
    - /run/secrets
  allowed_write_roots:
    - /workspace/output
  allowed_link_env:
    - WIPEME_PRIVATE_LINK
  allowed_passphrase_env:
    - WIPEME_PASSPHRASE
  allowed_source_env:
    - DATABASE_PASSWORD
    - API_TOKEN
  recovery_directory: /run/user/1000/wipeme-mcp-recovery
  recovery_ttl: 15m
  recovery_max_attempts: 5
  max_environment_sources: 16
  process_profiles: {}
```

The command-line `--access host|restricted` value overrides
`mcp.access_mode`. In restricted mode, empty roots or environment allowlists deny
the corresponding source or destination. In host mode, these allowlist fields are
not consulted.

Environment overrides for MCP policy should be minimal and explicitly documented.
Do not accept serialized process profiles or allowed roots from a single environment
variable. Configuration files containing policy must be owned by the current user
or root and not writable by group or others.

## 26. Internal architecture

Refactor behavior rather than invoking the CLI as a subprocess:

```text
cmd/wipeme
  ├── human CLI flag adapters
  └── MCP stdio adapter
          │
          ▼
internal/core typed operations
  ├── create
  ├── consume/decrypt
  ├── delete
  ├── file materialization
  ├── environment-file encoders
  ├── process profiles/execution
  └── recovery lifecycle
          │
          ▼
github.com/wipe-me/sdk/go/wipeme
```

The human CLI and MCP adapter call the same typed core. Do not shell out to
`wipeme`, duplicate SDK link validation, or fork cryptographic behavior.

## 27. Tests and completion criteria

Implementation is complete only when all of the following pass:

1. Existing CLI tests and help snapshots remain compatible.
2. Every MCP tool has schema, happy-path, invalid-input and sanitized-error tests.
3. Tests prove no direct-read/plaintext tool is registered.
4. Tests prove stdin/stdout contain valid MCP framing only.
5. Tests prove generated secrets, decrypted blocks, passphrases and process output
   never occur in MCP results, stderr logs or errors.
6. Tests cover automatic and manual links and prove fragments never reach HTTP.
7. Tests cover all link and passphrase source conflicts.
8. Tests cover multiple attachments, attachment-only messages, ordering, metadata
   cleanup, duplicate filenames and path traversal.
9. Tests cover every password preset, custom alphabets and class requirements by
   reusing existing password tests.
10. Tests cover process profile validation before retrieval, argv execution without
    a shell, minimal environment inheritance, protected names, timeout, signal,
    launch failure, nonzero exit and accepted exit codes.
11. Tests prove failed process, file and environment-file operations retain
    recovery, retries make no second GET, and successful retries wipe recovery.
12. Tests prove generated-secret retries reuse the exact same secret and release the
    link/QR only after accepted execution or successful file installation.
13. Tests prove abandoning an unreleased generated secret deletes its remote message
    before wiping recovery.
14. Tests verify dotenv, Docker, POSIX shell, and systemd encoding with quotes,
    backslashes, dollars, multiline values and refused NUL/Docker newlines.
15. Tests decode normal inline PNG QR output and compare the exact private link.
16. Tests cover recovery TTL, attempt exhaustion, startup cleanup, corrupt records,
    permissions and concurrent handle use.
17. Race tests ensure one recovery handle cannot execute concurrently.
18. Tests prove host mode uses OS-visible absolute paths and inherited environment
    without Wipe.me allowlists, while restricted mode denies access outside its
    configured roots and environment allowlists.
19. Tests prove `--access` overrides YAML and invalid access modes fail at startup.
20. Run `gofmt`, `go test ./...`, `go test -race ./...` and `go vet ./...`.
21. Run MCP protocol conformance/inspector tests against the built binary.
22. Run end-to-end Docker tests on the development network for create, consume,
    retry, delete, generated execution and QR flows.
23. Inspect Docker and MCP logs for known canary secrets.
24. Build GoReleaser snapshots and verify static macOS/Linux AMD64/ARM64 builds plus
    `.deb`, `.rpm`, Homebrew and direct archive layouts.
25. Verify Codex stdio configuration and at least one independent MCP client before
    release.

## 28. Distribution and documentation

- Target `v0.3.0-alpha.1` because MCP adds a new public interface and security model.
- `wipeme --help` adds `mcp` as a command; `wipeme mcp --help` documents stdio use
  and must not enumerate sensitive configuration values.
- README and Mintlify document MCP installation, each tool, process profiles,
  recovery behavior, QR capability risk and the absence of direct read.
- Publish an optional agent skill that describes safe tool selection and declares
  the MCP dependency. Package it as a plugin only after standalone MCP behavior is
  stable across clients.
- Release notes must explicitly state that MCP QR images and returned private links
  are bearer capabilities and may be retained by host transcripts.

## 29. Normative references

- [Official OpenAI Codex MCP documentation](https://developers.openai.com/codex/mcp/)
- [Official OpenAI skills documentation](https://developers.openai.com/codex/skills/)
- [MCP tool specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [Docker `--env-file` syntax](https://docs.docker.com/reference/cli/docker/container/run/#set-environment-variables--e---env---env-file)
- [Docker Compose `env_file` raw format](https://docs.docker.com/reference/compose-file/services/#format)
- [systemd `EnvironmentFile=` syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Environment)
