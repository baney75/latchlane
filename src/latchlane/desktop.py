"""Dedicated local Latchlane app-window and OS launcher support."""
import json
import os
from pathlib import Path
import platform
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from .cli import PORT, broker_url, data_dir, private_read
from .vault import VaultError, private_directory


MAC_BROWSERS = (
    "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
    str(Path.home() / "Applications/Vivaldi.app/Contents/MacOS/Vivaldi"),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)


def default_browser_path(system=None):
    system = system or platform.system()
    try:
        if system == "Darwin":
            script = "ObjC.import('AppKit'); var u=$.NSURL.URLWithString('https://latchlane.invalid'); var a=$.NSWorkspace.sharedWorkspace.URLForApplicationToOpenURL(u); a ? ObjC.unwrap(a.path) : '';"
            path = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", "-e", script], capture_output=True, text=True, timeout=3).stdout.strip()
            info = Path(path) / "Contents/Info.plist"
            if info.exists(): return str(Path(path) / "Contents/MacOS" / plistlib.loads(info.read_bytes())["CFBundleExecutable"])
        elif system == "Linux":
            desktop = subprocess.run(["xdg-settings", "get", "default-web-browser"], capture_output=True, text=True, timeout=3).stdout.strip()
            if not desktop: return None
            homes = [Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))]
            system_paths = [Path(path) for path in os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":") if path]
            paths = [path / "applications" for path in homes + system_paths]
            entry = next((path / desktop for path in paths if (path / desktop).is_file()), None)
            if not entry: return None
            in_desktop = False
            for line in entry.read_text(errors="ignore").splitlines():
                if line.startswith("["):
                    in_desktop = line == "[Desktop Entry]"
                elif in_desktop and line.startswith("Exec="):
                    try: command = shlex.split(line[5:])[0]
                    except (ValueError, IndexError): return None
                    if command in ("env", "flatpak", "snap"): return None
                    return shutil.which(command) or (command if Path(command).is_file() else None)
    except (OSError, subprocess.SubprocessError, KeyError, plistlib.InvalidFileException):
        pass
    return None


def browser_path(system=None):
    system = system or platform.system()
    default = default_browser_path(system)
    if default:
        if Path(default).is_file() and any(name in Path(default).name.lower() for name in ("vivaldi", "chrome", "chromium", "edge")):
            return default
        raise ValueError("Your default browser is not a supported Chromium browser. Use latchlane owner in Safari and Add to Dock, or use the browser console in Firefox; Latchlane will not substitute another browser.")
    if system == "Darwin":
        candidates = MAC_BROWSERS
    elif system == "Windows":
        roots = [os.environ.get("LOCALAPPDATA", ""), os.environ.get("PROGRAMFILES", ""), os.environ.get("PROGRAMFILES(X86)", "")]
        candidates = tuple(str(Path(root) / suffix) for root in roots if root for suffix in (
            "Vivaldi/Application/vivaldi.exe", "Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe"))
    else:
        candidates = tuple(filter(None, (shutil.which(name) for name in ("vivaldi-stable", "vivaldi", "google-chrome", "chromium", "chromium-browser", "microsoft-edge"))))
    return next((path for path in candidates if Path(path).is_file()), None)


def local_dialog(message, system=None):
    """Best-effort local error dialog. The static messages never contain secrets."""
    system = system or platform.system()
    try:
        if system == "Darwin" and Path("/usr/bin/osascript").exists():
            script = 'display alert "Latchlane" message ' + json.dumps(message) + " as critical"
            subprocess.run(["/usr/bin/osascript", "-e", script], check=False, timeout=8, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Windows":
            subprocess.run(["powershell", "-NoProfile", "-Command", "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show($args[0], 'Latchlane')", message], check=False, timeout=8, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif shutil.which("zenity"):
            subprocess.run(["zenity", "--error", "--title=Latchlane", "--text", message], check=False, timeout=8, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        pass
    print(message, file=sys.stderr)


def status(url):
    try:
        with httpx.Client(timeout=2, trust_env=False, follow_redirects=False) as client:
            response = client.get(url + "/api/status")
        if response.status_code != 200:
            return None
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("initialized"), bool) or not isinstance(body.get("locked"), bool):
            return None
        return body
    except (httpx.HTTPError, ValueError):
        return None


def start_host(port):
    command = [sys.executable, "-c", "from latchlane.cli import main; main()", "start", "--port", str(port), "--no-open"]
    return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def local_port(url):
    parsed = httpx.URL(url)
    if parsed.host not in ("127.0.0.1", "localhost") or parsed.scheme != "http":
        return None
    return parsed.port or 80


def startup_url(url):
    root = data_dir()
    ticket = root / "owner-ticket.local.json"
    if ticket.exists():
        try:
            ticket_url = json.loads(private_read(ticket))["url"]
            # It is safe to use only a local ticket belonging to this selected host.
            if ticket_url.startswith(url + "/"):
                return ticket_url
        except (KeyError, TypeError, ValueError, OSError, VaultError):
            pass
    return url + "/"


def open_app(url, profile=None, capture=False, system=None):
    browser = browser_path(system)
    if not browser:
        raise ValueError("No supported Chromium browser was found. Install Vivaldi, Chrome, Edge, or Chromium, then run latchlane app again.")
    profile = profile or data_dir() / "app-browser-profile"
    try:
        private_directory(profile)
    except VaultError as error:
        raise ValueError("Latchlane app profile is unsafe: " + str(error)) from None
    command = [browser, "--app=" + url, "--user-data-dir=" + str(profile), "--no-first-run", "--no-default-browser-check"]
    if capture:
        command.append("--window-size=520,760")
    try:
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        raise ValueError("Latchlane could not launch the supported browser. Check its installation, then run latchlane app again.") from None


def app(args, capture=None):
    url = broker_url(args.url)
    current = status(url)
    if current is None:
        port = local_port(url)
        if port is None:
            message = "The selected broker is unavailable. Only a local Latchlane address can be started automatically."
            local_dialog(message)
            raise ValueError(message)
        try:
            start_host(port)
        except OSError:
            message = "Latchlane could not start its local broker. Check the installation and local port, then run latchlane doctor."
            local_dialog(message)
            raise ValueError(message) from None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            current = status(url)
            if current is not None:
                break
            time.sleep(0.1)
        if current is None:
            message = "Latchlane did not become ready. Check that its local port is available, then run latchlane doctor."
            local_dialog(message)
            raise ValueError(message)
    try:
        target = startup_url(url)
        if capture:
            parts = urlsplit(target)
            query = {"capture": capture[0], "origin": capture[1], "window": "capture"}
            if capture[2] is not None: query["header"] = capture[2]
            if capture[3] is not None: query["prefix"] = capture[3]
            target = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
        open_app(target, capture=bool(capture), system=platform.system())
    except ValueError as error:
        local_dialog(str(error))
        raise


def installed_cli():
    candidate = Path(sys.argv[0])
    if candidate.is_absolute() and candidate.is_file():
        return str(candidate.resolve())
    found = shutil.which("latchlane")
    if found:
        return str(Path(found).resolve())
    raise ValueError("Cannot locate the installed latchlane command. Install it with uv tool install before creating an app launcher.")


def refuse_unrelated(path, marker):
    if path.exists() and marker not in path.read_text(errors="ignore"):
        raise ValueError("Refusing to replace an unrelated launcher at " + str(path))


def mac_icon(resources):
    source = Path(__file__).with_name("static") / "icons/mark-512.png"
    sips = shutil.which("sips"); iconutil = shutil.which("iconutil")
    if not source.exists() or not sips or not iconutil:
        return None
    try:
        with tempfile.TemporaryDirectory() as temp:
            iconset = Path(temp) / "Latchlane.iconset"; iconset.mkdir()
            for name, pixels in (("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64), ("128x128", 128), ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512), ("512x512", 512), ("512x512@2x", 1024)):
                output = iconset / f"icon_{name}.png"
                subprocess.run([sips, "-s", "format", "png", "-z", str(pixels), str(pixels), str(source), "--out", str(output)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            target = resources / "Latchlane.icns"
            subprocess.run([iconutil, "-c", "icns", str(iconset), "-o", str(target)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return target
    except (OSError, subprocess.SubprocessError):
        return None


def mac_launcher(cli):
    app_dir = Path.home() / "Applications/Latchlane.app"
    info = app_dir / "Contents/Info.plist"
    if app_dir.exists():
        if not info.exists(): raise ValueError("Refusing to replace an unrelated app at " + str(app_dir))
        try:
            if plistlib.loads(info.read_bytes()).get("CFBundleIdentifier") != "dev.latchlane.app":
                raise ValueError("Refusing to replace an unrelated app at " + str(app_dir))
        except plistlib.InvalidFileException:
            raise ValueError("Refusing to replace an unrelated app at " + str(app_dir)) from None
        existing = app_dir / "Contents/MacOS/Latchlane"
        if existing.exists(): refuse_unrelated(existing, " app ")
    macos = app_dir / "Contents/MacOS"; resources = app_dir / "Contents/Resources"
    macos.mkdir(parents=True, exist_ok=True); resources.mkdir(parents=True, exist_ok=True)
    (app_dir / "Contents/Info.plist").write_text("""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\"><dict><key>CFBundleExecutable</key><string>Latchlane</string><key>CFBundleIdentifier</key><string>dev.latchlane.app</string><key>CFBundleName</key><string>Latchlane</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleIconFile</key><string>Latchlane</string></dict></plist>""")
    launcher = macos / "Latchlane"
    launcher.write_text("#!/bin/sh\nexec " + shlex.quote(cli) + " app \"$@\"\n")
    launcher.chmod(0o755)
    mac_icon(resources)
    return app_dir


def linux_launcher(cli):
    desktop = Path.home() / ".local/share/applications/latchlane.desktop"
    desktop.parent.mkdir(parents=True, exist_ok=True)
    if desktop.exists(): refuse_unrelated(desktop, "Name=Latchlane")
    quoted = '"' + cli.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`").replace("%", "%%") + '"'
    desktop.write_text("[Desktop Entry]\nType=Application\nName=Latchlane\nExec=" + quoted + " app\nTerminal=false\nCategories=Utility;Security;\n")
    desktop.chmod(0o755)
    return desktop


def windows_launcher(cli):
    programs = Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))) / "Microsoft/Windows/Start Menu/Programs"
    programs.mkdir(parents=True, exist_ok=True)
    launcher = programs / "Latchlane.cmd"
    if launcher.exists(): refuse_unrelated(launcher, " app %*")
    if any(char in cli for char in "&|<>^%\r\n"):
        raise ValueError("Cannot safely create a Windows launcher for this command path.")
    launcher.write_text("@echo off\r\n" + subprocess.list2cmdline([cli, "app"]) + " %*\r\n")
    return launcher


def install_app(args):
    cli = installed_cli(); system = platform.system()
    if system == "Darwin": launcher = mac_launcher(cli)
    elif system == "Windows": launcher = windows_launcher(cli)
    else: launcher = linux_launcher(cli)
    print("Latchlane launcher installed at " + str(launcher))
    if not args.no_open:
        app(args)
