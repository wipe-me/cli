#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: sync-package-repositories.sh <artifacts-dir> <stable|preview> <working-dir>" >&2
  exit 2
fi

artifacts_dir=$1
channel=$2
working_dir=$3

: "${CF_R2_ACCOUNT_ID:?CF_R2_ACCOUNT_ID is required}"
: "${CF_R2_ACCESS_KEY_ID:?CF_R2_ACCESS_KEY_ID is required}"
: "${CF_R2_SECRET_ACCESS_KEY:?CF_R2_SECRET_ACCESS_KEY is required}"
: "${CF_R2_BUCKET:?CF_R2_BUCKET is required}"

export AWS_ACCESS_KEY_ID=$CF_R2_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$CF_R2_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION=auto

endpoint="https://${CF_R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
repository_dir="$working_dir/repository"

mkdir -p "$repository_dir"
aws s3 sync \
  "s3://$CF_R2_BUCKET/" \
  "$repository_dir/" \
  --endpoint-url "$endpoint" \
  --no-progress

"$(dirname "$0")/publish-package-repositories.sh" \
  "$artifacts_dir" \
  "$repository_dir" \
  "$channel"

aws s3 sync \
  "$repository_dir/" \
  "s3://$CF_R2_BUCKET/" \
  --endpoint-url "$endpoint" \
  --no-progress

echo "published Wipe.me $channel package repositories"
