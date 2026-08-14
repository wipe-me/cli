#!/usr/bin/env bash
set -euo pipefail
set +x

if [[ -z ${DATABASE_PASSWORD:-} ]]; then
  printf 'Deployment failed: DATABASE_PASSWORD was not injected.\n' >&2
  exit 1
fi

printf 'Deploying payments-api...\n'

# In production this process would pass its inherited DATABASE_PASSWORD directly to
# the deployment provider. The demonstration deliberately performs no real deploy
# and never prints, traces, or writes the credential.
printf 'Database credential installed.\n'
