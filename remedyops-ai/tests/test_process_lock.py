"""No network access, remote commands, or production files."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from process_lock import InterProcessLock, RemediationLockBusy, RemediationLockError


def test_lock_file_is_private_and_reusable(tmp_path):
    lock = InterProcessLock(tmp_path)
    with lock:
        path = tmp_path / ".remedyops.lock"
        assert path.is_file()
        assert path.stat().st_mode & 0o777 == 0o600
    with lock:
        pass


def test_second_process_style_owner_is_denied(tmp_path):
    first = InterProcessLock(tmp_path)
    second = InterProcessLock(tmp_path)
    with first:
        with pytest.raises(RemediationLockBusy):
            with second:
                pass
    with second:
        pass


def test_lock_released_on_exception(tmp_path):
    with pytest.raises(ValueError):
        with InterProcessLock(tmp_path):
            raise ValueError("simulated application error")
    with InterProcessLock(tmp_path):
        pass


def test_symlink_lock_file_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    (tmp_path / ".remedyops.lock").symlink_to(outside)
    with pytest.raises(RemediationLockError):
        with InterProcessLock(tmp_path):
            pass
    assert outside.read_text() == "unchanged"


def test_insecure_lock_file_permissions_fail_closed(tmp_path):
    path = tmp_path / ".remedyops.lock"
    path.touch(mode=0o600)
    path.chmod(0o666)
    with pytest.raises(RemediationLockError):
        with InterProcessLock(tmp_path):
            pass


def test_kernel_releases_lock_when_child_process_exits(tmp_path):
    code = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from process_lock import InterProcessLock\n"
        "with InterProcessLock(Path(sys.argv[1])):\n"
        "    print('READY', flush=True)\n"
        "    time.sleep(30)\n"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )
    try:
        assert child.stdout.readline().strip() == "READY"
        with pytest.raises(RemediationLockBusy):
            with InterProcessLock(tmp_path):
                pass
    finally:
        child.kill()
        child.communicate(timeout=5)
    with InterProcessLock(tmp_path):
        pass
