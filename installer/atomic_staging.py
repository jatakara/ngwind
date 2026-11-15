"""Fail-closed remote staging command builder; same-filesystem atomic no-clobber publish."""
import re
import shlex

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH = re.compile(r"^/home/[a-z_][a-z0-9_.-]{0,31}/omniesol-staging/[A-Za-z0-9_.-]{1,100}$")

def _safe(path):
    if not isinstance(path, str) or not _PATH.fullmatch(path) or ".." in path:
        raise ValueError("Unsafe remote staging path")
    return shlex.quote(path)

def checksum_command(partial):
    return 'sha256sum -- ' + _safe(partial) + ' | cut -d " " -f 1'

def publish_command(partial, canonical, digest):
    p, c = _safe(partial), _safe(canonical)
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ValueError("Invalid SHA-256")
    if partial == canonical or not partial.endswith(".partial"):
        raise ValueError("Not a distinct partial path")
    # Hard-link creation is atomic and refuses overwrite; both paths must share a filesystem.
    return (f'set -eu; umask 077; '
            f'test -f {p} && test ! -L {p} || exit 74; '
            f'test "$(sha256sum -- {p} | cut -d " " -f 1)" = {digest} || exit 75; '
            f'if test -e {c} || test -L {c}; then '
            f'test ! -L {c} && test -f {c} || exit 76; '
            f'test "$(sha256sum -- {c} | cut -d " " -f 1)" = {digest} || exit 73; '
            f'else '
            f'ln -- {p} {c} || {{ '
            f'test ! -L {c} && test -f {c} && '
            f'test "$(sha256sum -- {c} | cut -d " " -f 1)" = {digest}; }} || exit 77; '
            f'fi; '
            f'test "$(sha256sum -- {c} | cut -d " " -f 1)" = {digest} || exit 78; '
            f'rm -f -- {p}')

def cleanup_command(partial):
    return 'rm -f -- ' + _safe(partial)
