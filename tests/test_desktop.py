from argparse import Namespace
import json
from pathlib import Path
import socket
import shlex
import subprocess
import time

import httpx

from latchlane import desktop


def test_app_starts_only_missing_local_host_and_uses_ticket(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop, "data_dir", lambda: tmp_path)
    ticket = tmp_path / "owner-ticket.local.json"
    ticket.write_text(json.dumps({"url": "http://127.0.0.1:19474/#fixture-ticket"}))
    ticket.chmod(0o600)
    states = iter((None, {"initialized": False, "locked": True}))
    opened = []
    monkeypatch.setattr(desktop, "status", lambda url: next(states))
    monkeypatch.setattr(desktop, "start_host", lambda port: opened.append(("host", port)))
    monkeypatch.setattr(desktop, "open_app", lambda url, **kwargs: opened.append(("app", url)))
    desktop.app(Namespace(url="http://127.0.0.1:19474"))
    assert opened == [("host", 19474), ("app", "http://127.0.0.1:19474/#fixture-ticket")]
    assert not (tmp_path / "unattended.key").exists()


def test_remote_app_never_starts_a_local_host(monkeypatch):
    monkeypatch.setattr(desktop, "status", lambda url: None)
    monkeypatch.setattr(desktop, "local_dialog", lambda message: None)
    monkeypatch.setattr(desktop, "start_host", lambda port: (_ for _ in ()).throw(AssertionError("must not start remote host")))
    try:
        desktop.app(Namespace(url="https://fixture.ts.net:8447"))
    except ValueError as error:
        assert "Only a local" in str(error)
    else:
        raise AssertionError("remote failure must be visible")


def test_open_app_uses_selected_browser_normal_profile(monkeypatch):
    command = []
    monkeypatch.setattr(desktop, "browser_path", lambda system=None: "/fixture/Vivaldi")
    monkeypatch.setattr(desktop.subprocess, "Popen", lambda args, **kwargs: command.extend(args))
    desktop.open_app("http://127.0.0.1:19474/")
    assert command == ["/fixture/Vivaldi", "--app=http://127.0.0.1:19474/", "--no-first-run", "--no-default-browser-check"]
    assert not any(value.startswith("--user-data-dir=") for value in command)


def test_open_app_uses_explicit_fixture_profile_without_remote_debugging(tmp_path, monkeypatch):
    command = []
    monkeypatch.setattr(desktop, "browser_path", lambda system=None: "/fixture/Vivaldi")
    monkeypatch.setattr(desktop.subprocess, "Popen", lambda args, **kwargs: command.extend(args))
    desktop.open_app("http://127.0.0.1:19474/", profile=tmp_path / "profile")
    assert "--app=http://127.0.0.1:19474/" in command
    assert "--user-data-dir=" + str(tmp_path / "profile") in command
    assert not any("remote-debug" in value for value in command)
    assert (tmp_path / "profile").is_dir()


def test_background_host_uses_real_cli_argv_and_starts_fixture_host(tmp_path, monkeypatch):
    monkeypatch.setenv("LATCHLANE_HOME", str(tmp_path))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    process = desktop.start_host(port)
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{port}/api/status", trust_env=False).status_code == 200: break
            except httpx.HTTPError: pass
            time.sleep(.1)
        else: raise AssertionError("fixture broker did not start")
        assert "--no-unattended" not in process.args
    finally:
        process.terminate(); process.wait(timeout=5)


def test_capture_uses_compact_app_query(monkeypatch):
    opened=[]
    monkeypatch.setattr(desktop, "status", lambda url: {"initialized": True, "locked": False})
    monkeypatch.setattr(desktop, "open_app", lambda url, **kwargs: opened.append((url, kwargs)))
    desktop.app(Namespace(url="http://127.0.0.1:19474"), capture=("fixture", "https://api.example.com", "X-API-Key", ""))
    assert opened[0][0] == "http://127.0.0.1:19474/?capture=fixture&origin=https%3A%2F%2Fapi.example.com&window=capture&header=X-API-Key&prefix="
    assert opened[0][1]["capture"] is True


def test_capture_preserves_first_setup_fragment(tmp_path, monkeypatch):
    ticket = tmp_path / "owner-ticket.local.json"
    ticket.write_text(json.dumps({"url": "http://127.0.0.1:19474/#fixture-bootstrap"})); ticket.chmod(0o600)
    opened=[]
    monkeypatch.setattr(desktop, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(desktop, "status", lambda url: {"initialized": False, "locked": True})
    monkeypatch.setattr(desktop, "open_app", lambda url, **kwargs: opened.append(url))
    desktop.app(Namespace(url="http://127.0.0.1:19474"), capture=("fixture", "https://api.example.com", None, None))
    assert opened == ["http://127.0.0.1:19474/?capture=fixture&origin=https%3A%2F%2Fapi.example.com&window=capture#fixture-bootstrap"]


def test_macos_default_browser_uses_jxa_stdout(tmp_path, monkeypatch):
    app = tmp_path / "Vivaldi.app"; info = app / "Contents/Info.plist"; info.parent.mkdir(parents=True)
    import plistlib
    info.write_bytes(plistlib.dumps({"CFBundleExecutable": "Vivaldi"}))
    executable = app / "Contents/MacOS/Vivaldi"; executable.parent.mkdir(); executable.touch()
    class Result: stdout=str(app) + "\n"
    monkeypatch.setattr(desktop.subprocess, "run", lambda *args, **kwargs: Result())
    assert desktop.default_browser_path("Darwin") == str(executable)


def test_linux_default_browser_parses_quoted_exec_in_xdg_data_home(tmp_path, monkeypatch):
    executable = tmp_path / "Browser With Space"; executable.touch()
    entry = tmp_path / "applications/example.desktop"; entry.parent.mkdir()
    entry.write_text("[Desktop Entry]\nExec=\"" + str(executable) + "\" --new-window %U\n")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", "")
    class Result: stdout="example.desktop\n"
    monkeypatch.setattr(desktop.subprocess, "run", lambda *args, **kwargs: Result())
    assert desktop.default_browser_path("Linux") == str(executable)


def test_unsupported_default_browser_opens_through_os_default(tmp_path, monkeypatch):
    safari = tmp_path / "Safari"; safari.touch()
    command = []
    monkeypatch.setattr(desktop, "default_browser_path", lambda system: str(safari))
    monkeypatch.setattr(desktop.subprocess, "Popen", lambda args, **kwargs: command.extend(args))
    desktop.open_app("http://127.0.0.1:19474/", system="Darwin")
    assert command == ["open", "http://127.0.0.1:19474/"]


def test_unresolved_linux_default_opens_through_xdg_without_browser_substitution(monkeypatch):
    command = []
    monkeypatch.setattr(desktop, "default_browser_path", lambda system: None)
    monkeypatch.setattr(desktop.subprocess, "Popen", lambda args, **kwargs: command.extend(args))
    desktop.open_app("http://127.0.0.1:19474/", system="Linux")
    assert command == ["xdg-open", "http://127.0.0.1:19474/"]


def test_mac_launcher_is_per_user_and_refuses_unrelated(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(desktop, "mac_icon", lambda resources: None)
    url = "http://127.0.0.1:19474"
    launcher = desktop.mac_launcher("/stable/latchlane", url)
    executable = launcher / "Contents/MacOS/Latchlane"
    assert launcher == tmp_path / "Applications/Latchlane.app"
    assert shlex.split(executable.read_text().splitlines()[1]) == ["exec", "/stable/latchlane", "app", "--url", url, "$@"]
    original = (launcher / "Contents/Info.plist").read_bytes()
    executable.write_text("unrelated")
    try:
        desktop.mac_launcher("/stable/latchlane", url)
    except ValueError as error:
        assert "unrelated" in str(error)
    else:
        raise AssertionError("must preserve an unrelated app")
    assert executable.read_text() == "unrelated"
    assert (launcher / "Contents/Info.plist").read_bytes() == original


def test_windows_launcher_rejects_hostile_command_path(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    try:
        desktop.windows_launcher(r"C:\safe&bad\latchlane.exe", "http://127.0.0.1:19474")
    except ValueError as error:
        assert "safely" in str(error)
    else:
        raise AssertionError("hostile path must not become a cmd launcher")


def test_windows_launcher_upgrades_own_launcher_and_persists_url(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    launcher = tmp_path / "Microsoft/Windows/Start Menu/Programs/Latchlane.cmd"
    launcher.parent.mkdir(parents=True)
    launcher.write_text('@echo off\r\n"C:\\stable\\latchlane.exe" app %*\r\n')
    url = "http://127.0.0.1:19474"
    assert desktop.windows_launcher(r"C:\stable\latchlane.exe", url) == launcher
    assert subprocess.list2cmdline([r"C:\stable\latchlane.exe", "app", "--url", url]) + " %*" in launcher.read_text()


def test_linux_launcher_persists_custom_url_uses_xdg_data_home_and_icon(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data home"))
    url = "http://127.0.0.1:19474"
    launcher = desktop.linux_launcher("/stable/latchlane with space", url)
    assert launcher == tmp_path / "data home/applications/latchlane.desktop"
    contents = launcher.read_text()
    assert 'Exec="/stable/latchlane with space" app --url "http://127.0.0.1:19474"' in contents
    assert "Icon=" + str(Path(desktop.__file__).with_name("static") / "icons/mark-512.png") in contents


def test_install_app_persists_validated_custom_url(monkeypatch):
    installed = []
    monkeypatch.setattr(desktop, "installed_cli", lambda: "/stable/latchlane")
    monkeypatch.setattr(desktop.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(desktop, "mac_launcher", lambda cli, url: installed.append((cli, url)) or Path("/fixture/Latchlane.app"))
    desktop.install_app(Namespace(url="http://127.0.0.1:19474", no_open=True))
    assert installed == [("/stable/latchlane", "http://127.0.0.1:19474")]


def test_launchers_refuse_custom_url_with_space_or_metacharacter(tmp_path, monkeypatch):
    monkeypatch.setattr(desktop.Path, "home", classmethod(lambda cls: tmp_path))
    for value in ("http://127.0.0.1:9473 bad", "http://127.0.0.1:9473;touch"):
        try:
            desktop.linux_launcher("/stable/latchlane", value)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe custom URL must not become a launcher argument")
