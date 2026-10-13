#!/bin/sh
set -eu

: "${CNYOS_LOCAL_NODE_BIN:?CNYOS_LOCAL_NODE_BIN is required}"

case "$CNYOS_LOCAL_NODE_BIN" in
  /*) ;;
  *) echo 'CNYOS_LOCAL_NODE_BIN must be absolute' >&2; exit 1 ;;
esac

# This is only the inner sanitized launcher. It is not a trust bootstrap:
# an outside-PR controller must first pin the exact repository commit/tree and
# this Node executable before introducing staging credentials. Remove preload
# injection variables before the credential-bearing Node process starts.
unset NODE_OPTIONS NODE_PATH LD_PRELOAD DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH
export CNYOS_LOCAL_SANITIZED_LAUNCH=1

case "$0" in
  */*) SCRIPT_PARENT=${0%/*} ;;
  *) SCRIPT_PARENT=. ;;
esac
SCRIPT_DIR=$(CDPATH= cd -- "$SCRIPT_PARENT" && /bin/pwd -P)
exec "$CNYOS_LOCAL_NODE_BIN" "$SCRIPT_DIR/run-local-bounded-treatment-uat.mjs"
