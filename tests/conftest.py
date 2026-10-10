import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def sock_dir() -> Iterator[Path]:
    """A fresh short directory for unix sockets, removed afterwards.

    macOS caps a socket path at 104 bytes, which pytest's tmp_path
    exceeds. mkdtemp under $TMPDIR is short, never reused, and lies
    inside the build directory in the nix sandbox. A fixed /tmp name
    met stale sockets from earlier runs whenever a PID repeated.
    """
    path = Path(tempfile.mkdtemp(prefix="pmdns"))
    yield path
    shutil.rmtree(path, ignore_errors=True)
