"""ResolvConf installer: delimited block in, only our block out."""

import os
import stat

from pymacdns.installer import BEGIN_MARK, END_MARK, ResolvConf


def test_install_prepends_block(tmp_path):
    target = tmp_path / "resolv.conf"
    target.write_text("nameserver 9.9.9.9\nsearch example.com\n")
    inst = ResolvConf(str(target), ["127.0.0.1", "::1"])
    inst.install()
    text = target.read_text()
    assert text.startswith(
        f"{BEGIN_MARK}\nnameserver 127.0.0.1\nnameserver ::1\n{END_MARK}\n"
    )
    assert text.endswith("nameserver 9.9.9.9\nsearch example.com\n")


def test_install_missing_file_creates(tmp_path):
    target = tmp_path / "resolv.conf"
    inst = ResolvConf(str(target), ["127.0.0.1"])
    inst.install()
    assert target.read_text() == f"{BEGIN_MARK}\nnameserver 127.0.0.1\n{END_MARK}\n"


def test_reinstall_idempotent_and_refreshes(tmp_path):
    target = tmp_path / "resolv.conf"
    target.write_text("nameserver 9.9.9.9\n")
    inst = ResolvConf(str(target), ["127.0.0.1"])
    inst.install()
    once = target.read_text()
    inst.install()
    assert target.read_text() == once
    assert once.count(BEGIN_MARK) == 1
    ResolvConf(str(target), ["127.0.0.2"]).install()
    text = target.read_text()
    assert "nameserver 127.0.0.2\n" in text
    assert "nameserver 127.0.0.1\n" not in text
    assert text.endswith("nameserver 9.9.9.9\n")
    assert text.count(BEGIN_MARK) == 1


def test_cleanup_restores_original_byte_for_byte(tmp_path):
    target = tmp_path / "resolv.conf"
    before_text = "nameserver 9.9.9.9\nsearch example.com\n# trailing, no newline"
    target.write_bytes(before_text.encode())
    before = target.read_bytes()
    inst = ResolvConf(str(target), ["127.0.0.1"])
    inst.install()
    assert target.read_bytes() != before
    inst.cleanup()
    assert target.read_bytes() == before


def test_cleanup_removes_file_it_created(tmp_path):
    target = tmp_path / "resolv.conf"
    inst = ResolvConf(str(target), ["127.0.0.1"])
    inst.install()
    assert target.exists()
    inst.cleanup()
    assert not target.exists()


def test_cleanup_ignores_foreign_file(tmp_path):
    target = tmp_path / "resolv.conf"
    target.write_text("nameserver 9.9.9.9\n")
    before = target.read_bytes()
    ResolvConf(str(target), ["127.0.0.1"]).cleanup()
    assert target.read_bytes() == before
    empty = tmp_path / "empty.conf"
    empty.write_text("")
    ResolvConf(str(empty), ["127.0.0.1"]).cleanup()
    assert empty.read_bytes() == b""


def test_cleanup_missing_file_is_noop(tmp_path):
    ResolvConf(str(tmp_path / "nope.conf"), ["127.0.0.1"]).cleanup()


def test_lone_begin_refuses_install_and_survives_cleanup(tmp_path):
    target = tmp_path / "resolv.conf"
    target.write_text(f"nameserver 9.9.9.9\n{BEGIN_MARK}\nnameserver 1.1.1.1\n")
    before = target.read_bytes()
    try:
        ResolvConf(str(target), ["127.0.0.1"]).install()
    except ValueError:
        pass
    else:
        raise AssertionError("lone BEGIN must refuse install")
    assert target.read_bytes() == before
    ResolvConf(str(target), ["127.0.0.1"]).cleanup()
    assert target.read_bytes() == before


def test_mode_preserved(tmp_path):
    target = tmp_path / "resolv.conf"
    target.write_text("nameserver 9.9.9.9\n")
    os.chmod(target, 0o600)
    inst = ResolvConf(str(target), ["127.0.0.1"])
    inst.install()
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    inst.cleanup()
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert target.read_text() == "nameserver 9.9.9.9\n"


def test_symlink_is_followed_not_replaced(tmp_path):
    """Like /etc/resolv.conf -> ../var/run/resolv.conf: the link stays."""
    real = tmp_path / "real-resolv.conf"
    real.write_text("nameserver 9.9.9.9\n")
    link = tmp_path / "resolv.conf"
    link.symlink_to(real.name)
    inst = ResolvConf(str(link), ["127.0.0.1"])
    inst.install()
    assert link.is_symlink()
    assert BEGIN_MARK in real.read_text()
    inst.cleanup()
    assert link.is_symlink()
    assert real.read_bytes() == b"nameserver 9.9.9.9\n"
