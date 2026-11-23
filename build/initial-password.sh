#!/bin/bash
# One-time appliance password for image builds.
# When this script generates the password it writes it to the path in $1
# with mode 600. Set FGUARD_INITIAL_PASSWORD to reuse one.

fguard_initial_password() {
  local dest="${1:-}"
  if [ -n "${FGUARD_INITIAL_PASSWORD:-}" ]; then
    export FGUARD_INITIAL_PASSWORD
    return 0
  fi
  FGUARD_INITIAL_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  export FGUARD_INITIAL_PASSWORD
  if [ -n "$dest" ]; then
    umask 077
    printf '%s\n' "$FGUARD_INITIAL_PASSWORD" > "$dest"
    chmod 600 "$dest" 2>/dev/null || true
    echo "Initial password written to $dest (mode 600). It expires at first login."
  fi
}

fguard_password_hash() {
  if [ -z "${FGUARD_INITIAL_PASSWORD:-}" ]; then
    echo "FGUARD_INITIAL_PASSWORD is not set" >&2
    return 1
  fi
  if python3 - <<'PY'
import os, sys
password = os.environ["FGUARD_INITIAL_PASSWORD"]
try:
    import crypt
    print(crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512)))
except Exception:
    sys.exit(1)
PY
  then
    return 0
  fi
  openssl passwd -6 "$FGUARD_INITIAL_PASSWORD"
}
