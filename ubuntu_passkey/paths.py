"""XDG locations and file helpers."""

import os
import tempfile


def _xdg(var, fallback):
    base = os.environ.get(var) or os.path.expanduser(fallback)
    return os.path.join(base, "ubuntu-passkey")


def data_dir():
    return _xdg("XDG_DATA_HOME", "~/.local/share")


def config_dir():
    return _xdg("XDG_CONFIG_HOME", "~/.config")


def atomic_write(path, data, mode=0o600):
    """Write ``data`` to ``path`` atomically with restrictive permissions."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
