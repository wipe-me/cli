#!/usr/bin/env bash
set -euo pipefail
set +x

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-"$script_dir/agent-human-isolated-deployment-pairing.cast"}

if [[ ${WIPEME_CAST_SCENE:-} == 1 ]]; then
  magenta=$'\033[1;35m'
  blue=$'\033[1;34m'
  muted=$'\033[2m'
  reset=$'\033[0m'

  prompt() {
    printf '%srunner@deploy%s:%s/casts%s$ ' "$magenta" "$reset" "$blue" "$reset"
  }

  type_text() {
    local text=$1
    local offset=0
    local -a widths=(5 7 4 6 5 7)
    local index=0
    local width

    while (( offset < ${#text} )); do
      width=${widths[index % ${#widths[@]}]}
      printf '%s' "${text:offset:width}"
      offset=$((offset + width))
      index=$((index + 1))
      sleep 0.27
    done
  }

  enter() {
    sleep 0.35
    printf '\n'
  }

  type_line() {
    prompt
    type_text "$1"
    enter
  }

  progress() {
    printf '\rEncrypting... ▰▰▰▰▰▰▰▰▰▰▰▰ 100%%'
    sleep 0.45
    printf '\rUploading...  ▰▰▰▰▰▰▰▰▰▰▰▰ 100%%\n'
  }

  printf '\033[2J\033[H'
  sleep 0.45

  type_line '# Pair a human with an isolated deployment tool'
  type_line '# Advanced demonstration—not the simplest workflow for ordinary sharing.'
  printf '\n'

  type_line 'wipeme --generate-pass --set-env WIPEME_PASSPHRASE -- ./deployment-runner'
  progress
  printf 'Private link: https://wipe.me/7Km-Np4-XqR#8Wd-H3v-Tz6-BcP\n'
  sleep 0.8

  type_line '# Human opened the one-time link and saved the pairing passphrase.'
  type_line '# If it had been consumed first, pairing would fail and restart.'
  type_line '# Pairing confirmed. The agent only carried the link.'
  printf '\n'

  type_line 'wipeme --generate-pass --set-env DATABASE_PASSWORD -- ./deploy.sh'
  progress
  printf 'Private link: https://wipe.me/K7mQ-2xR8\n'
  printf 'Deploying payments-api...\n'
  sleep 0.35
  printf 'Database credential installed.\n'
  sleep 0.8

  type_line '# The deployment received DATABASE_PASSWORD directly.'
  type_line '# The human can open the link with the pairing passphrase.'
  type_line '# The agent relayed both links—but learned neither accepted password.'
  printf '\n%sAdvanced demo: the security boundary is the isolated trusted runner.%s\n' "$muted" "$reset"
  sleep 1
  exit 0
fi

WIPEME_CAST_SCENE=1 asciinema record \
  --overwrite \
  --title 'Pair a human with an isolated deployment tool' \
  --idle-time-limit 1.25 \
  --window-size 100x30 \
  --command "bash $script_dir/record-agent-human-isolated-deployment.sh" \
  "$output"
