"""XDG folders, including the move from the project's old name."""

from linux_passkey import paths


def test_old_folder_is_carried_over(env):
    old = env / "data" / "ubuntu-passkey"
    old.mkdir(parents=True)
    (old / "credentials.enc").write_bytes(b"secret")
    new = paths.data_dir()
    assert new.endswith("linux-passkey")
    assert (env / "data" / "linux-passkey" / "credentials.enc").read_bytes() == b"secret"
    assert not old.exists()


def test_new_folder_wins(env):
    (env / "config" / "ubuntu-passkey").mkdir(parents=True)
    (env / "config" / "linux-passkey").mkdir(parents=True)
    assert paths.config_dir().endswith("linux-passkey")
    assert (env / "config" / "ubuntu-passkey").exists()
