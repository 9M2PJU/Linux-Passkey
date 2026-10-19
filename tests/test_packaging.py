"""The distribution packages and the hints that name their packages."""

import os
import re

import linux_passkey
from linux_passkey import uhid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def test_every_package_has_the_same_version():
    version = linux_passkey.__version__
    assert re.search(r"^linux-passkey \(([^)-]+)", read("debian", "changelog")).group(1) == version
    spec = read("packaging", "rpm", "linux-passkey.spec")
    assert re.search(r"^Version:\s*(\S+)", spec, re.M).group(1) == version
    assert re.search(r"^\* .* - (\S+)-\d+$", spec, re.M).group(1) == version
    assert re.search(r"^pkgver=(\S+)", read("packaging", "arch", "PKGBUILD"), re.M).group(1) == version


def fake_system(tmp_path, os_id, module=False):
    release = os.uname().release
    hid = tmp_path / "modules" / release / "kernel" / "drivers" / "hid"
    hid.mkdir(parents=True)
    if module:
        (hid / "uhid.ko.zst").write_bytes(b"")
    (tmp_path / "os-release").write_text(os_id)
    return {"modules": str(tmp_path / "modules"), "os_release": str(tmp_path / "os-release")}


def test_hint_loads_the_module_when_it_exists(tmp_path):
    hint = uhid.missing_module_hint(**fake_system(tmp_path, "ID=arch\n", module=True))
    assert "modprobe uhid" in hint


def test_hint_names_the_package_on_debian_and_ubuntu(tmp_path):
    hint = uhid.missing_module_hint(**fake_system(tmp_path, 'ID=linuxmint\nID_LIKE="ubuntu debian"\n'))
    assert "apt install linux-modules-extra-" in hint


def test_hint_names_the_package_on_fedora(tmp_path):
    hint = uhid.missing_module_hint(**fake_system(tmp_path, 'ID=fedora\n'))
    assert "dnf install kernel-modules-core-" in hint


def test_hint_elsewhere_names_no_package_manager(tmp_path):
    hint = uhid.missing_module_hint(**fake_system(tmp_path, 'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n'))
    assert "apt" not in hint and "dnf" not in hint and "CONFIG_UHID" in hint


def test_hint_after_a_kernel_update(tmp_path):
    (tmp_path / "modules").mkdir()
    hint = uhid.missing_module_hint(modules=str(tmp_path / "modules"), os_release=str(tmp_path / "none"))
    assert "restart" in hint
