"""Human setup and agent commands. Credentials never appear in CLI output."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit
import webbrowser
import httpx
import uvicorn
from filelock import FileLock, Timeout
from platformdirs import user_data_path
from . import __version__
from .vault import Vault, VaultError, private_directory, private_read, atomic_write
from .server import CollectionCreate

PORT = 9473


class BrokerError(ValueError):
    """A safe broker response classification for callers that need the status."""
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status

def data_dir():
    return Path(os.environ.get("LATCHLANE_HOME", user_data_path("Latchlane", appauthor=False)))


def tailscale_bin():
    return shutil.which("tailscale") or ("/Applications/Tailscale.app/Contents/MacOS/Tailscale" if Path("/Applications/Tailscale.app/Contents/MacOS/Tailscale").exists() else None)


def tail_status():
    exe = tailscale_bin()
    if not exe: return {}
    try:
        p = subprocess.run([exe,"status","--json"], capture_output=True, timeout=8)
        return json.loads(p.stdout) if p.returncode == 0 else {}
    except (ValueError, OSError, subprocess.TimeoutExpired): return {}


def broker_url(value):
    p = urlsplit(value)
    if p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("Use only the broker origin, without a path or credentials.")
    try:
        p.port
    except ValueError:
        raise ValueError("Use a valid broker port.") from None
    if p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost"):
        return value.rstrip("/")
    if p.scheme == "https" and p.hostname and p.hostname.endswith(".ts.net"):
        return value.rstrip("/")
    raise ValueError("Use local HTTP or your private https://device.tailnet.ts.net address.")


def network_error(error, outcome_uncertain=False):
    if isinstance(error, httpx.TimeoutException):
        message = "Broker did not respond in time. Check that it is running."
    elif isinstance(error, httpx.ConnectError):
        message = "Cannot reach the broker. Check its address, network connection, and Tailscale if used."
    else:
        message = "Could not contact the broker. Check its address and network connection."
    if outcome_uncertain:
        message += " The operation may have reached the broker; check the owner console and provider state before retrying."
    return ValueError(message)


def broker_error(status, path=""):
    if status == 401:
        return BrokerError(status, "Agent is unpaired or revoked. Pair again from the owner console.")
    if status == 403:
        if path.endswith("/consume"):
            return BrokerError(status, "Approval was denied or already consumed. Create a new request if access is still needed.")
        return BrokerError(status, "Broker denied the operation. An approval or pairing code may have expired; ask the owner to create a fresh one.")
    if status == 404:
        return BrokerError(status, "Broker no longer recognizes that key or request. It may have expired or already been consumed.")
    if status == 410:
        return BrokerError(status, "Approval expired. Create a new request; Latchlane will not retry it automatically.")
    if status == 423:
        return BrokerError(status, "Vault locked. Open the owner console to unlock it.")
    if status in (502, 503, 504):
        return BrokerError(status, "The provider could not be reached or its response was uncertain. Check provider state before retrying.")
    if status == 429:
        return BrokerError(status, "Broker is busy. Wait for pending requests to expire, then try again.")
    if status == 422:
        return BrokerError(status, "Broker rejected the request format. Check the command arguments and try again.")
    return BrokerError(status, f"Broker declined the operation (HTTP {status}). Check the owner console.")


class Client:
    def __init__(self, root=None):
        self.root = root or data_dir()
        config = json.loads(private_read(self.root / "agent.local.json"))
        self.url = broker_url(config["url"])
        self.token = config["token"]

    def call(self, method, path, body=None):
        try:
            with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as c:
                r = c.request(method, self.url + path, json=body, headers={"Authorization":"Bearer " + self.token, "X-Latchlane":"1"})
        except httpx.HTTPError as e:
            raise network_error(e, outcome_uncertain=method.upper() not in ("GET", "HEAD")) from None
        if r.status_code >= 300:
            raise broker_error(r.status_code, path)
        try:
            return r.json()
        except ValueError:
            message = "Broker returned an invalid response. Check the broker."
            if method.upper() not in ("GET", "HEAD"):
                message += " The operation may have reached the broker; check the owner console and provider state before retrying."
            raise ValueError(message) from None


def probe_broker(url, token=None):
    """Return secret-free readiness facts. This only reads status and key names."""
    result = {"broker_reachable": None, "broker_state": "unavailable", "broker_version": None}
    try:
        with httpx.Client(timeout=3, trust_env=False, follow_redirects=False) as c:
            status = c.get(url + "/api/status")
            if status.status_code != 200:
                result["broker_reachable"] = False
                result["broker_state"] = f"http_{status.status_code}"
                return result
            payload = status.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("initialized"), bool) or not isinstance(payload.get("locked"), bool) or not isinstance(payload.get("version"), str):
                result["broker_reachable"] = False
                result["broker_state"] = "invalid_response"
                return result
            result["broker_reachable"] = True
            result["broker_version"] = payload["version"]
            if not payload.get("initialized"):
                result["broker_state"] = "not_initialized"
            elif payload.get("locked"):
                result["broker_state"] = "locked"
            else:
                result["broker_state"] = "ready"
            if token is None:
                return result
            pairing = c.get(url + "/api/keys", headers={"Authorization": "Bearer " + token, "X-Latchlane": "1"})
    except httpx.HTTPError:
        return result
    except (TypeError, ValueError):
        result["broker_reachable"] = False
        result["broker_state"] = "invalid_response"
        return result

    if pairing.status_code == 200:
        try:
            names = pairing.json()
        except ValueError:
            names = None
        if isinstance(names, dict) and isinstance(names.get("keys"), list):
            result["agent_pairing_valid"] = True
            result["agent_pairing_state"] = "valid"
        else:
            result["agent_pairing_valid"] = None
            result["agent_pairing_state"] = "unavailable_invalid_response"
    elif pairing.status_code == 401:
        result["agent_pairing_valid"] = False
        result["agent_pairing_state"] = "revoked_or_unpaired"
    elif pairing.status_code == 423:
        result["agent_pairing_valid"] = None
        result["agent_pairing_state"] = "unavailable_vault_locked"
    else:
        result["agent_pairing_valid"] = None
        result["agent_pairing_state"] = "unavailable"
    return result


def doctor(args):
    root = data_dir()
    profile = root / "agent.local.json"
    result = {
        # Preserve these established fields for scripts that consume doctor output.
        "vault_exists": (root / "store.vault").exists(),
        "agent_paired": profile.exists(),
        "unattended": (root / "unattended.key").exists(),
        "tailscale_installed": bool(tailscale_bin()),
        "tailscale_connected": tail_status().get("BackendState") == "Running",
    }
    url = broker_url(args.url) if args.url else None
    token = None
    if profile.exists():
        try:
            config = json.loads(private_read(profile))
            profile_url = broker_url(config["url"])
            profile_token = config["token"]
            if not isinstance(profile_token, str) or not profile_token:
                raise ValueError("Invalid agent profile.")
        except (KeyError, TypeError, ValueError, OSError):
            result.update({"agent_pairing_valid": False, "agent_pairing_state": "invalid_profile"})
            profile_url = None
        else:
            if url and url != profile_url:
                result.update({"agent_pairing_valid": False, "agent_pairing_state": "profile_url_mismatch"})
            else:
                url = url or profile_url
                token = profile_token
                result.update({"agent_pairing_valid": None, "agent_pairing_state": "unavailable"})
    else:
        result.update({"agent_pairing_valid": False, "agent_pairing_state": "not_configured"})
        url = url or f"http://127.0.0.1:{PORT}"

    if url:
        result.update(probe_broker(url, token))
        if token is None and result["agent_pairing_state"] == "not_configured":
            # The broker can be ready even though this machine has no pairing.
            result["agent_pairing_valid"] = False
    else:
        result.update({"broker_reachable": None, "broker_state": "not_configured"})
    print(json.dumps(result, indent=2))


def wait_operation(client, operation):
    request = client.call("POST", "/api/requests", operation)
    if request["status"] == "pending": print("Waiting for approval in the owner console…", file=sys.stderr, flush=True)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        result = client.call("POST", "/api/requests/" + request["id"] + "/consume")
        if result.get("status") != "pending": return result
        time.sleep(2)
    raise ValueError("Approval expired. No automatic retry.")


def collection_spec(path):
    """Load an agent collection request without ever accepting credential data."""
    try:
        raw = path.read_bytes()
        if len(raw) > 100000:
            raise ValueError()
        parsed = json.loads(raw)
        return CollectionCreate.model_validate(parsed).model_dump()
    except (OSError, ValueError, TypeError):
        raise ValueError("Collection spec must be a metadata-only JSON request with recognized fields.") from None


def collection_result(reply, names):
    """A deliberately small public result shared by CLI and MCP."""
    if not isinstance(reply, dict) or not isinstance(reply.get("id"), str) or reply.get("status") not in ("pending", "completed", "cancelled"):
        raise ValueError("Broker returned an invalid collection response.")
    return {"id": reply["id"], "status": reply["status"], "names": names}


def open_collection_window(client, reply):
    collection_id = reply.get("id") if isinstance(reply, dict) else None
    # The host deliberately returns a relative path. Do not accept a URL from a
    # network response as authority to open another origin or inject a ticket.
    if not isinstance(collection_id, str) or reply.get("owner_path") != "/?collection=" + collection_id:
        raise ValueError("Broker returned an invalid collection owner path.")
    from .desktop import open_app
    open_app(client.url + reply["owner_path"])


def collect(args):
    body = collection_spec(args.spec_file)
    names = [item["name"] for item in body["items"]]
    client = Client()
    try:
        reply = client.call("POST", "/api/collections", body)
    except BrokerError as error:
        # A collection must be paired and its server must verify that pairing.
        # In wait mode, make the owner-unlock workflow one local browser action,
        # then verify the host state and retry exactly once.
        if not args.wait or error.status != 423:
            raise
        if not args.no_open:
            from .desktop import open_app
            open_app(client.url + "/")
        unlock_deadline = time.monotonic() + 900
        state = probe_broker(client.url, client.token)
        while state.get("broker_state") != "ready" and time.monotonic() < unlock_deadline:
            time.sleep(2)
            state = probe_broker(client.url, client.token)
        if state.get("broker_state") != "ready":
            raise ValueError("Vault locked. Open the owner console to unlock it, then run collect again.") from None
        reply = client.call("POST", "/api/collections", body)
    result = collection_result(reply, names)
    if not args.no_open:
        open_collection_window(client, reply)
    if not args.wait:
        print(json.dumps(result))
        return
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        time.sleep(2)
        status = client.call("GET", "/api/collections/" + result["id"])
        result = collection_result(status, names)
        if result["status"] != "pending":
            print(json.dumps(result))
            return
    raise ValueError("Collection expired. No automatic retry.")


def start(args):
    root=data_dir(); private_directory(root)
    with FileLock(str(root / "host.lock"), timeout=0):
        from .server import create_app
        ts = tail_status()
        dns = ts.get("Self", {}).get("DNSName", "").rstrip(".")
        hosts = [dns + ":8447"] if dns.endswith(".ts.net") else []
        app=create_app(root, port=args.port, hosts=hosts, initial_mode=args.initial_mode)
        auto = root / "unattended.key"
        if auto.exists(): app.state.vault.unlock(private_read(auto).decode())
        link=f"http://127.0.0.1:{args.port}/"
        if not app.state.vault.path.exists():
            link += "#" + app.state.bootstrap
            atomic_write(root / "owner-ticket.local.json", json.dumps({"url": link}).encode())
        elif auto.exists():
            link += "#owner=" + app.state.bootstrap
            atomic_write(root / "owner-ticket.local.json", json.dumps({"url": link}).encode())
        if not args.no_open:
            def open_when_ready():
                for _ in range(100):
                    try:
                        r=httpx.get(f"http://127.0.0.1:{args.port}/api/status",timeout=.3,trust_env=False)
                        if r.status_code==200: webbrowser.open(link); return
                    except httpx.HTTPError: pass
                    time.sleep(.1)
            threading.Thread(target=open_when_ready, daemon=True).start()
        print(f"Latchlane is starting at http://127.0.0.1:{args.port}", flush=True)
        if not app.state.vault.path.exists() and args.no_open:
            print("First setup needs a browser. Run without --no-open, or use latchlane init locally.",flush=True)
        uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False, proxy_headers=True, forwarded_allow_ips="127.0.0.1", log_level="warning")


def initialize(args):
    root=data_dir(); private_directory(root)
    with FileLock(str(root / "host.lock"), timeout=0):
        v=Vault(root)
        if v.path.exists(): raise ValueError("Vault exists. Use the owner console to change its mode.")
        if args.unattended:
            password=secrets.token_urlsafe(48)
        else:
            password=getpass.getpass("New vault passphrase (14+ characters): ")
            if password!=getpass.getpass("Repeat passphrase: "): raise ValueError("Passphrases differ.")
        v.initialize(password)
        v.data["mode"]=args.mode
        v.save()
        if args.unattended:
            atomic_write(root / "unattended.key",password.encode())
            print("Unattended mode: the local unlock file grants access to this vault. Keep this OS account trusted.")
        print("Vault initialized. Mode: " + args.mode)


def connect(args):
    exe=tailscale_bin()
    if not exe:
        print("Install Tailscale: https://tailscale.com/download\nCreate an account: https://login.tailscale.com/start\nThen run latchlane connect again.")
        if not args.no_open: webbrowser.open("https://tailscale.com/download")
        return
    status=tail_status()
    if status.get("BackendState")!="Running":
        print("Complete Tailscale’s browser sign-in. You can create an account there.",flush=True)
        result=subprocess.run([exe,"up"])
        if result.returncode: raise ValueError("Tailscale sign-in did not complete. Open its app, sign in, and retry.")
        status=tail_status()
    dns=status.get("Self",{}).get("DNSName","").rstrip(".")
    if not dns.endswith(".ts.net"): raise ValueError("Tailscale is not ready. Enable MagicDNS and retry.")
    existing=subprocess.run([exe,"serve","status","--json"],capture_output=True,timeout=10)
    if existing.returncode: raise ValueError("Could not inspect existing Tailscale Serve configuration.")
    config=json.loads(existing.stdout or b'{}')
    # Never replace an unrelated Serve/Funnel route on the dedicated port.
    if config.get("TCP",{}).get("8447") or any(k.endswith(":8447") for k in config.get("Web",{})):
        target=json.dumps(config.get("Web",{}).get(dns+":8447",{}))
        if f"127.0.0.1:{args.port}" not in target:
            raise ValueError("Tailscale port 8447 is already in use. Existing routes were preserved.")
        print("An existing route uses this port. Inspect tailscale serve status before changing it.")
        return
    result=subprocess.run([exe,"serve","--bg","--https=8447",f"http://127.0.0.1:{args.port}"])
    if result.returncode: raise ValueError("Complete Tailscale’s HTTPS consent, then run connect again.")
    print(f"Private address: https://{dns}:8447\nRestart latchlane start if Tailscale was not connected when it launched.\nSign in on your phone or pair another agent. Never enable Tailscale Funnel for this vault.")


def pair(args):
    root=data_dir(); private_directory(root)
    url=broker_url(args.url)
    existing = root / "agent.local.json"
    if existing.exists():
        current = json.loads(private_read(existing))
        if broker_url(current["url"]) != url:
            raise ValueError("This profile belongs to another vault. Use a separate LATCHLANE_HOME.")
        try:
            with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as c:
                status = c.get(url + "/api/keys", headers={"Authorization": "Bearer " + current["token"], "X-Latchlane": "1"}).status_code
        except httpx.HTTPError:
            raise ValueError("Could not verify the existing pairing. Its credential was preserved.") from None
        if status == 200: raise ValueError("This agent is already paired. Revoke it in the owner console before replacing it.")
        if status != 401: raise ValueError("Unlock the existing vault and retry pairing. Its credential was preserved.")
        print("The previous pairing was revoked. Enter a new code to reconnect.")
    code=getpass.getpass("Pairing code from owner console (hidden): ")
    try:
        with httpx.Client(timeout=15,trust_env=False,follow_redirects=False) as c:
            r=c.post(url+"/api/pair",json={"code":code,"name":args.name},headers={"X-Latchlane":"1"})
    except httpx.HTTPError as e: raise network_error(e, outcome_uncertain=True) from None
    if r.status_code != 200: raise broker_error(r.status_code, "/api/pair")
    try:
        token=r.json()["token"]
    except (KeyError, TypeError, ValueError):
        raise ValueError("Broker returned an invalid pairing response. It may have accepted the code; check the owner console before retrying.") from None
    atomic_write(root/"agent.local.json",json.dumps({"url":url,"token":token}).encode())
    print("Paired. Credential saved locally; its value was not displayed.")


def mcp(collections_only=False):
    client=Client()
    unlock_opened = False
    tools=[{"name":"latchlane_keys","description":"List available credential names and destinations, never values.","annotations":{"readOnlyHint":True},"inputSchema":{"type":"object","properties":{},"additionalProperties":False}},
      {"name":"latchlane_request","description":"Request an authenticated HTTPS operation. Approval is enforced by the broker. Use the returned ID with latchlane_consume.","inputSchema":{"type":"object","properties":{"key":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","POST","PUT","PATCH","DELETE"]},"path":{"type":"string"},"body":{"type":"string"},"purpose":{"type":"string"}},"required":["key","path","purpose"],"additionalProperties":False}},
      {"name":"latchlane_consume","description":"Execute an approved request once. Pending requests return pending; do not repeatedly poll faster than every 2 seconds.","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":False}},
      {"name":"latchlane_collect","description":"Ask the owner to add one or more named credentials. Send metadata only: names, kinds, HTTPS destinations, and purpose. It never accepts or returns credential values.","inputSchema":{"type":"object","properties":{"purpose":{"type":"string","minLength":1,"maxLength":300},"items":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"object","properties":{"name":{"type":"string"},"kind":{"type":"string","enum":["api_key","password"]},"origin":{"type":"string"},"header":{"type":"string"},"prefix":{"type":"string"}},"required":["name","origin"],"additionalProperties":False}},"open_window":{"type":"boolean"}},"required":["purpose","items"],"additionalProperties":False}},
      {"name":"latchlane_collection_status","description":"Read a collection request status and requested names. Only the paired requesting agent can read it; values and usernames are never returned.","annotations":{"readOnlyHint":True},"inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":False}}]
    if collections_only:
        tools = [tool for tool in tools if tool["name"] in ("latchlane_collect", "latchlane_collection_status")]
    for line in sys.stdin:
        msg={}
        try:
            if len(line)>100000: raise ValueError()
            msg=json.loads(line)
            if "id" not in msg: continue
            method=msg.get("method")
            if method=="initialize": result={"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"latchlane","version":__version__}}
            elif method=="ping": result={}
            elif method=="tools/list": result={"tools":tools}
            elif method=="tools/call":
                p=msg.get("params",{}); a=p.get("arguments",{}); name=p.get("name")
                if collections_only and name not in ("latchlane_collect", "latchlane_collection_status"):
                    raise ValueError("This MCP server only accepts collection tools.")
                if name=="latchlane_keys": data=client.call("GET","/api/keys")
                elif name=="latchlane_request":
                    if set(a)-{"key","method","path","body","purpose"}: raise ValueError("Unsupported fields.")
                    data=client.call("POST","/api/requests",a|{"kind":"http"})
                elif name=="latchlane_consume":
                    rid=a["id"]
                    if not re.fullmatch(r"[A-Za-z0-9_-]{20,40}",rid): raise ValueError("Invalid request ID.")
                    data=client.call("POST","/api/requests/"+rid+"/consume")
                elif name=="latchlane_collect":
                    if not isinstance(a, dict) or set(a)-{"purpose","items","open_window"}: raise ValueError("Unsupported fields.")
                    open_window = a.pop("open_window", True)
                    if not isinstance(open_window, bool): raise ValueError("Invalid open_window.")
                    body = CollectionCreate.model_validate(a).model_dump()
                    try:
                        reply = client.call("POST", "/api/collections", body)
                    except BrokerError as error:
                        if error.status != 423: raise
                        if open_window and not unlock_opened:
                            from .desktop import open_app
                            unlock_opened = True
                            try: open_app(client.url + "/")
                            except (OSError, ValueError): pass
                        data = {"status":"unlock_required", "names":[item["name"] for item in body["items"]], "message":"The owner must unlock Latchlane, then retry this collection request."}
                    else:
                        unlock_opened = False
                        if open_window: open_collection_window(client, reply)
                        data = collection_result(reply, [item["name"] for item in body["items"]])
                elif name=="latchlane_collection_status":
                    if not isinstance(a, dict) or set(a)!={"id"} or not isinstance(a["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,40}",a["id"]): raise ValueError("Invalid collection ID.")
                    reply = client.call("GET", "/api/collections/" + a["id"])
                    data = collection_result(reply, reply.get("names", []))
                else: raise ValueError("Unknown tool.")
                if isinstance(data,dict) and "value" in data: raise ValueError("Raw keys are not available through MCP.")
                result={"content":[{"type":"text","text":json.dumps(data)}]}
            else:
                print(json.dumps({"jsonrpc":"2.0","id":msg["id"],"error":{"code":-32601,"message":"Method not found"}}),flush=True); continue
            print(json.dumps({"jsonrpc":"2.0","id":msg["id"],"result":result}),flush=True)
        except Exception:
            print(json.dumps({"jsonrpc":"2.0","id":msg.get("id"),"error":{"code":-32603,"message":"Operation failed. Check the owner console; secret values hidden."}}),flush=True)


def main():
    p=argparse.ArgumentParser(prog="latchlane",description="Your keys. Your agents. Your call.")
    p.add_argument("--version", action="version", version=__version__)
    sub=p.add_subparsers(dest="command",required=True)
    s=sub.add_parser("start",help="Start your vault and open the owner console");s.add_argument("--port",type=int,default=PORT);s.add_argument("--no-open",action="store_true");s.add_argument("--initial-mode",choices=["ask","auto","yolo"],default="ask",help="Explicit first-setup mode; defaults to Always ask")
    s=sub.add_parser("init",help="Initialize from a terminal (start gives a browser setup)");s.add_argument("--mode",choices=["ask","auto","yolo"],default="ask");s.add_argument("--unattended",action="store_true",help="Store a local unlock file; readable by this OS user")
    s=sub.add_parser("connect",help="Guided Tailscale sign-in and private HTTPS");s.add_argument("--port",type=int,default=PORT);s.add_argument("--no-open",action="store_true")
    s=sub.add_parser("pair",help="Pair this agent with an owner-generated code");s.add_argument("url");s.add_argument("--name",default="My agent")
    sub.add_parser("keys",help="List names without revealing values")
    s=sub.add_parser("request",help="Make an authenticated API request");s.add_argument("key");s.add_argument("path");s.add_argument("--method",default="GET");s.add_argument("--purpose",required=True);s.add_argument("--body-file",type=Path)
    s=sub.add_parser("run",help="Request a raw key and pass it to one trusted child process");s.add_argument("key");s.add_argument("variable");s.add_argument("--purpose",required=True);s.add_argument("argv",nargs=argparse.REMAINDER)
    s=sub.add_parser("collect",help="Ask the owner to add one or more metadata-only credential requests");s.add_argument("--spec-file",type=Path,required=True);s.add_argument("--wait",action="store_true",help="Poll collection status for up to 15 minutes");s.add_argument("--no-open",action="store_true",help="Do not open the local owner window")
    s=sub.add_parser("capture",help="Open the owner’s named clipboard capture form");s.add_argument("name");s.add_argument("--origin",default="");s.add_argument("--header",choices=["Authorization","X-API-Key","API-KEY","api-key","x-goog-api-key"]);s.add_argument("--prefix",choices=["none","bearer","basic"]);s.add_argument("--url",default=f"http://127.0.0.1:{PORT}")
    s=sub.add_parser("mcp",help="Run the MCP stdio server for a paired agent");s.add_argument("--collections-only",action="store_true",help="Expose only metadata-only credential collection tools")
    s=sub.add_parser("install-skill",help="Install the bundled skill for Codex or another agent");s.add_argument("--directory",type=Path,default=Path.home()/".codex/skills/latchlane")
    s=sub.add_parser("owner",help="Open the local owner console; use --url for a custom port");s.add_argument("--url",help="Local or private broker origin, for example http://127.0.0.1:9474")
    s=sub.add_parser("doctor",help="Check local readiness without reading key values");s.add_argument("--url",help="Local or private broker origin to probe")
    s=sub.add_parser("app",help="Open Latchlane in a dedicated app window");s.add_argument("--url",default=f"http://127.0.0.1:{PORT}",help="Local or private broker origin")
    s=sub.add_parser("install-app",help="Install a per-user Latchlane app launcher");s.add_argument("--url",default=f"http://127.0.0.1:{PORT}",help="Local or private broker origin");s.add_argument("--no-open",action="store_true",help="Install without opening the app")
    args=p.parse_args()
    try:
        if args.command=="start": start(args)
        elif args.command=="init": initialize(args)
        elif args.command=="connect": connect(args)
        elif args.command=="pair": pair(args)
        elif args.command=="keys": print(json.dumps(Client().call("GET","/api/keys"),indent=2))
        elif args.command=="request":
            body=args.body_file.read_text() if args.body_file else ""
            result=wait_operation(Client(),{"key":args.key,"path":args.path,"method":args.method,"body":body,"purpose":args.purpose})
            print(json.dumps(result,indent=2))
        elif args.command=="run":
            argv=args.argv[1:] if args.argv[:1]==["--"] else args.argv
            if not argv or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",args.variable): raise ValueError("Provide a valid environment variable and command after --.")
            result=wait_operation(Client(),{"key":args.key,"kind":"lease","purpose":args.purpose})
            env=os.environ.copy();env[args.variable]=result["value"]
            sys.exit(subprocess.run(argv,env=env).returncode)
        elif args.command=="collect": collect(args)
        elif args.command=="capture":
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",args.name): raise ValueError("Use a lowercase key name.")
            from .desktop import app
            prefix={"none":"", "bearer":"Bearer ", "basic":"Basic "}.get(args.prefix)
            app(args, capture=(args.name, args.origin, args.header, prefix));print("Capture window opened. Sign in, confirm the destination, then choose Watch next copy. Do not paste secrets into chat.")
        elif args.command=="owner":
            if args.url:
                webbrowser.open(broker_url(args.url) + "/")
                print("Owner window opened.")
            else:
                ticket=data_dir()/"owner-ticket.local.json"
                if ticket.exists():
                    try:
                        ticket_url=json.loads(private_read(ticket))["url"]
                        ticket_origin=broker_url(urlsplit(ticket_url)._replace(path="", query="", fragment="").geturl())
                    except (KeyError, TypeError, ValueError, OSError):
                        raise ValueError("Owner ticket is invalid. Restart the host, or use latchlane owner --url with its current address.") from None
                    if probe_broker(ticket_origin)["broker_reachable"] is not True:
                        raise ValueError("Owner ticket is stale or its host is unavailable. Restart the host, or use latchlane owner --url with its current address.")
                    webbrowser.open(ticket_url)
                    print("Owner window opened. If the one-use session expired, restart the host to issue a fresh one.")
                else:
                    webbrowser.open(f"http://127.0.0.1:{PORT}/")
        elif args.command=="mcp": mcp(args.collections_only)
        elif args.command=="install-skill":
            source=Path(__file__).with_name("SKILL.md")
            if not source.exists(): source=Path(__file__).parents[2]/"skills/latchlane/SKILL.md"
            dest=args.directory/"SKILL.md"
            if dest.exists(): raise ValueError("Skill exists. Review and update it deliberately.")
            args.directory.mkdir(parents=True,exist_ok=True);dest.write_text(source.read_text());print("Latchlane skill installed.")
        elif args.command=="doctor": doctor(args)
        elif args.command=="app":
            from .desktop import app
            app(args)
        elif args.command=="install-app":
            from .desktop import install_app
            install_app(args)
    except (ValueError,VaultError,Timeout,FileNotFoundError) as e:
        print(str(e) if not isinstance(e,FileNotFoundError) else "Not set up yet. Run latchlane start or latchlane pair.",file=sys.stderr);sys.exit(1)
    except KeyboardInterrupt: pass
    except Exception:
        print("Operation failed. No credentials were printed. Check the owner console and doctor.",file=sys.stderr);sys.exit(1)
