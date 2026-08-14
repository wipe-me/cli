# Wipe.me CLI recordings

This directory contains the reusable Docker environment for recording Wipe.me CLI
demos. It connects to the local development stack by default and keeps asciinema's
account identity in Docker volumes between container rebuilds and restarts.

## Start the recorder

Start the Wipe.me development stack first so that the external
`wipe-me-dev_default` network and its `web` service exist. Then build and start the
recorder:

```sh
cd cli/casts
docker compose up -d --build
docker compose exec recorder wipeme --version
```

The defaults are:

- Public links: `https://wipe.me`
- API requests: `https://wipe.me`
- Development network: `wipe-me-dev_default`

Explicitly override the URLs when rehearsing against the local development stack:

```sh
WIPEME_SERVER_URL=http://localhost:5173 \
WIPEME_API_URL=http://web:5173 \
WIPEME_DEV_NETWORK=wipe-me-dev_default \
docker compose up -d
```

If an older ad-hoc container already owns the name `wipeme-casts`, remove that
container once before running Compose:

```sh
docker rm -f wipeme-casts
docker compose up -d --build
```

## Authenticate asciinema

Before the first upload, open a shell in the container and authenticate with your
asciinema.org account:

```console
$ docker compose exec recorder bash
linuxbrew@wipeme:/casts$ asciinema auth
```

Follow the URL shown by asciinema and approve it while signed into the intended
account. Authentication survives `docker compose down`, image rebuilds, and new
containers because Compose preserves both of these paths in named volumes:

- `/home/linuxbrew/.config/asciinema`
- `/home/linuxbrew/.local/state/asciinema`

Do not use `docker compose down --volumes` unless you intentionally want to remove
the saved asciinema identity and authenticate again.

Upload a completed recording from inside the same container:

```console
linuxbrew@wipeme:/casts$ asciinema upload --visibility unlisted human-to-human-private-sharing.cast
```

## Record a cast

```sh
docker compose exec recorder \
  env 'PS1=\[\033[1;35m\]demo@wipeme\[\033[0m\]:\[\033[1;34m\]\w\[\033[0m\]\$ ' \
  asciinema record \
    --overwrite \
    --title 'Wipe.me CLI: human-to-human private sharing' \
    --idle-time-limit 1.25 \
    --window-size 100x30 \
    --command 'bash --noprofile --norc -i' \
    /casts/human-to-human-private-sharing.cast
```

The explicit ANSI escapes color `demo@wipeme` magenta and the working directory
blue. They are necessary because `--noprofile --norc` deliberately avoids the
machine-specific shell configuration that normally supplies a colored prompt.

The Compose service defaults to production for publishable casts. If the container
was started with local URL overrides for rehearsal, recreate it without those
overrides before recording the final cast. Before uploading, verify that every
recorded public link starts with `https://wipe.me/` and that neither `localhost` nor
`127.0.0.1` appears in the file.

Play it locally before uploading:

```sh
docker compose exec recorder \
  asciinema play /casts/human-to-human-private-sharing.cast
```

For a human-to-human flow, include the recipient side after creation. Type the
command normally, insert the opaque link quickly, and always quote it because the
shell treats `#` as the beginning of a comment:

```sh
wipeme read 'https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7'
```

Use the relevant read form in more specialized casts when it adds value:

```sh
# Save attachments without overwriting existing files
wipeme read --output-dir ./received \
  'https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7'

# Non-interactive agent or CI consumption
wipeme read --non-interactive \
  'https://wipe.me/1K7-mQ2-xR8#7YW-HMf-k9J-CB7'
```

Render a GIF with `agg`:

```sh
docker compose exec recorder \
  agg --font-size 16 \
  /casts/human-to-human-private-sharing.cast \
  /casts/human-to-human-private-sharing.gif
```

Keep the GIF basename identical to its source cast so the relationship remains
obvious in the repository.

## Cast filenames

Recordings are committed to this repository, so give every cast a descriptive,
stable kebab-case filename. The name should identify the audience or workflow and
the primary action being demonstrated:

```text
human-to-human-private-sharing.cast
agent-read-and-exec-secret.cast
attachments-metadata-removal.cast
```

Avoid generic or chronological names such as `demo.cast`, `wipeme-demo.cast`,
`test.cast`, or `final-v2.cast`. Re-record an existing workflow into its established
filename with `--overwrite` rather than creating numbered revisions.

### Advanced Agent → Human pairing cast

`record-agent-human-isolated-deployment.sh` creates the deterministic offline cast
`agent-human-isolated-deployment-pairing.cast`. It reproduces the verified Wipe.me
CLI output order with correctly formatted fictional links, so recording it never
creates a live message:

```sh
docker compose exec recorder \
  bash /casts/record-agent-human-isolated-deployment.sh

docker compose exec recorder \
  agg --font-size 16 \
  /casts/agent-human-isolated-deployment-pairing.cast \
  /casts/agent-human-isolated-deployment-pairing.gif
```

The accompanying `deployment-runner` is the real trusted-runner fixture. It requires
the human to enter the pairing passphrase without terminal echo and fails visibly if
the value does not match the generated `WIPEME_PASSPHRASE`. `deploy.sh` verifies that
`DATABASE_PASSWORD` was injected without printing or writing it. The cast reenacts
that workflow offline because its links must remain fictional.

The initial automatic link is a detectable one-time pairing attempt. If the agent or
another party consumes it first, the human cannot recover that round's passphrase,
trusted-runner confirmation fails, and the whole pairing command must be rerun. Only
a passphrase from a round successfully confirmed by the human is accepted. An
untrusted relay can therefore deny service by repeatedly consuming links, but cannot
silently substitute a consumed round as the accepted pairing secret.

## Recording pace

Keep future casts quick enough to remain engaging while leaving commands readable:

- Target roughly 15–20 visible characters per second.
- Animate commands and human-entered text; do not reveal a complete line instantly.
- With terminal automation, emit irregular bursts of 4–7 characters about every
  250 ms. This looks typed while avoiding an unnaturally slow per-key cadence.
- Opaque links and existing environment-variable values may appear instantly or much
  faster than explanatory commands.
- Pause about 300–500 ms before Enter and 500–900 ms after important output.
- Use `--idle-time-limit 1.25` to cap accidental dead time.
- Aim for a focused cast of about 25–40 seconds.
- Use an obviously temporary rehearsal filename outside the repository, such as
  `/tmp/wipeme-rehearsal.cast`, and remember that successful local uploads count
  toward the three-messages-per-minute anonymous development quota.

Before publishing, replay the entire cast and confirm that every command is legible,
all expected links were produced, and no error or unintended secret appears.
