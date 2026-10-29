#!/bin/sh
# Cloud Linux runtime only. The package helper binds @SOURCE_SHA256@ to its input.
set -eu
umask 077
fail() { printf 'AI Lens Cowork: %s\n' "$1" >&2; exit 2; }
[ "$#" -eq 1 ] || fail 'expected one hook event'
event=$1
case "$event" in
  SessionStart|SessionEnd|PreToolUse|PostToolUse|PostToolUseFailure) ;;
  *) fail 'unsupported hook event' ;;
esac
[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || fail 'this plugin requires a Linux x86_64 hook runtime'
plugin=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
uid=$(id -u)
key=$(printf '%s\n%s\n' "$plugin" '@SOURCE_SHA256@' | sha256sum)
key=${key%% *}
runtime="/tmp/ai-lens-cowork-$uid-$key"
# /tmp is the runtime-local namespace, not a host-supplied or environment path.
[ ! -L /tmp ] && [ -d /tmp ] || fail '/tmp must be a real directory'
[ "$(stat -c %u /tmp)" = 0 ] || fail '/tmp must be owned by root'
case "$(stat -c %a /tmp)" in 1777|1770) ;; *) fail '/tmp must have sticky directory permissions' ;; esac
if mkdir -m 700 "$runtime" 2>/dev/null; then :; fi
[ ! -L "$runtime" ] && [ -d "$runtime" ] || fail 'unsafe runtime directory'
[ "$(stat -c %u "$runtime")" = "$uid" ] && [ "$(stat -c %a "$runtime")" = 700 ] || fail 'runtime directory must be owned by this user with mode 0700'
state="$runtime/state"
lens="$plugin/scripts/runtime/linux-x86_64/agent-lens"
engine="$plugin/scripts/runtime/linux-x86_64/libagent_lens_engine.so"
for file in "$lens" "$engine" "$plugin/scripts/rules.yaml"; do
  [ ! -L "$file" ] && [ -f "$file" ] || fail 'missing or symlinked plugin runtime file'
done
[ -x "$lens" ] || chmod u+x "$lens"
# Refuse an existing output/initialization marker that redirects outside this scope.
for file in "$runtime/events.jsonl" "$runtime/initialized"; do
  if [ -e "$file" ] || [ -L "$file" ]; then
    [ ! -L "$file" ] && [ -f "$file" ] || fail 'unsafe runtime file'
    [ "$(stat -c %u "$file")" = "$uid" ] && [ "$(stat -c %a "$file")" = 600 ] || fail 'runtime files must be owned by this user with mode 0600'
  fi
done
lock="$runtime/init.lock"
attempt=0
until mkdir -m 700 "$lock" 2>/dev/null; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || fail 'initialization lock timed out; inspect runtime state'
  sleep 0.05
done
trap 'rmdir "$lock" 2>/dev/null || :' 0
trap 'exit 2' 1 2 15
if [ -e "$state" ] || [ -L "$state" ]; then
  [ ! -L "$state" ] && [ -d "$state" ] || fail 'unsafe state directory'
  [ "$(stat -c %u "$state")" = "$uid" ] && [ "$(stat -c %a "$state")" = 700 ] || fail 'state directory must be owned by this user with mode 0700'
else
  mkdir -m 700 "$state"
fi
if [ -e "$state/config.json" ] || [ -L "$state/config.json" ]; then
  [ ! -L "$state/config.json" ] && [ -f "$state/config.json" ] || fail 'unsafe state config'
  [ "$(stat -c %u "$state/config.json")" = "$uid" ] && [ "$(stat -c %a "$state/config.json")" = 600 ] || fail 'state config must be owned by this user with mode 0600'
else
  [ ! -e "$runtime/initialized" ] || fail 'initialized state config is missing; refusing to restart collection'
  "$lens" --state "$state" start --output "$runtime/events.jsonl" --rules "$plugin/scripts/rules.yaml" </dev/null >/dev/null
  : > "$runtime/initialized"
fi
# A previously disabled config is deliberately left disabled. Only explicit start enables it.
rmdir "$lock"
trap - 0 1 2 15
exec "$lens" --state "$state" hook --agent cowork --event "$event"
