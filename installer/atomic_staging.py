"""Remote staging command builder. Commands are quoted; no shell input from users."""
import re
import shlex

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH = re.compile(r"^/home/[a-z_][a-z0-9_.-]{0,31}/omniesol-staging/[A-Za-z0-9_.-]{1,100}$")

def _safe(path):
    if not _PATH.fullmatch(path) or ".." in path:
        raise ValueError("Unsafe remote staging path")
    return shlex.quote(path)

def checksum_command(partial):
    return 'sha256sum -- ' + _safe(partial) + ' | cut -d " " -f 1'

def publish_command(partial, canonical, digest):
    p, c = _safe(partial), _safe(canonical)
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Invalid SHA-256")
    if partial == canonical or not partial.endswith(".partial"):
        raise ValueError("Not a distinct partial path")
    # Refuse to replace an existing different artifact; re-upload of same hash is idempotent.
    return (f'set -eu; umask 077; if test -e {c}; then '
            f'old=$(sha256sum -- {c} | cut -d " " -f 1); '
            f'test "$old" = {digest} || exit 73; rm -f -- {p}; '
            f'else mv -n -- {p} {c}; fi; '
            f'test "$(sha256sum -- {c} | cut -d " " -f 1)" = {digest}')

def cleanup_command(partial):
    return 'rm -f -- ' + _safe(partial)
