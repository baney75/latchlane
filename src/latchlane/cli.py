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
from .vault import Vault, VaultError, private_directory, private_read, atomic_write

PORT = 9473

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
    if p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost"):
        return value.rstrip("/")
    if p.scheme == "https" and p.hostname and p.hostname.endswith(".ts.net"):
        return value.rstrip("/")
    raise ValueError("Use local HTTP or your private https://device.tailnet.ts.net address.")


class Client:
    def __init__(self, root=None):
        self.root = root or data_dir()
        config = json.loads(private_read(self.root / "agent.local.json"))
        self.url = broker_url(config["url"])
        self.token = config["token"]

    def call(self, method, path, body=None):
        with httpx.Client(timeout=30, trust_env=False, follow_redirects=False) as c:
            r = c.request(method, self.url + path, json=body, headers={"Authorization":"Bearer " + self.token, "X-Latchlane":"1"})
        if r.status_code >= 300:
            # Only known broker error strings, never dump bodies or headers.
            if r.status_code == 423: raise ValueError("Vault locked. Open the owner console to unlock it.")
            if r.status_code == 401: raise ValueError("Agent is unpaired or revoked. Pair again from the owner console.")
            raise ValueError(f"Broker declined the operation (HTTP {r.status_code}). Check the owner console.")
        return r.json()


def wait_operation(client, operation):
    request = client.call("POST", "/api/requests", operation)
    if request["status"] == "pending": print("Waiting for approval in the owner console…", file=sys.stderr, flush=True)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        result = client.call("POST", "/api/requests/" + request["id"] + "/consume")
        if result.get("status") != "pending": return result
        time.sleep(2)
    raise ValueError("Approval expired. No automatic retry.")


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
        if r.status_code!=200: raise ValueError("Pairing failed. Generate a fresh code in the owner console.")
        token=r.json()["token"]
    except httpx.HTTPError: raise ValueError("Cannot reach that vault. Check Tailscale and the address.") from None
    atomic_write(root/"agent.local.json",json.dumps({"url":url,"token":token}).encode())
    print("Paired. Credential saved locally; its value was not displayed.")


def mcp():
    client=Client()
    tools=[{"name":"latchlane_keys","description":"List available credential names and destinations, never values.","inputSchema":{"type":"object","properties":{}}},
      {"name":"latchlane_request","description":"Request an authenticated HTTPS operation. Approval is enforced by the broker. Use the returned ID with latchlane_consume.","inputSchema":{"type":"object","properties":{"key":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","POST","PUT","PATCH","DELETE"]},"path":{"type":"string"},"body":{"type":"string"},"purpose":{"type":"string"}},"required":["key","path","purpose"]}},
      {"name":"latchlane_consume","description":"Execute an approved request once. Pending requests return pending; do not repeatedly poll faster than every 2 seconds.","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}]
    for line in sys.stdin:
        msg={}
        try:
            if len(line)>100000: raise ValueError()
            msg=json.loads(line)
            if "id" not in msg: continue
            method=msg.get("method")
            if method=="initialize": result={"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"latchlane","version":"0.1.1"}}
            elif method=="ping": result={}
            elif method=="tools/list": result={"tools":tools}
            elif method=="tools/call":
                p=msg.get("params",{}); a=p.get("arguments",{}); name=p.get("name")
                if name=="latchlane_keys": data=client.call("GET","/api/keys")
                elif name=="latchlane_request":
                    if set(a)-{"key","method","path","body","purpose"}: raise ValueError("Unsupported fields.")
                    data=client.call("POST","/api/requests",a|{"kind":"http"})
                elif name=="latchlane_consume":
                    rid=a["id"]
                    if not re.fullmatch(r"[A-Za-z0-9_-]{20,40}",rid): raise ValueError("Invalid request ID.")
                    data=client.call("POST","/api/requests/"+rid+"/consume")
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
    sub=p.add_subparsers(dest="command",required=True)
    s=sub.add_parser("start",help="Start your vault and open the owner console");s.add_argument("--port",type=int,default=PORT);s.add_argument("--no-open",action="store_true");s.add_argument("--initial-mode",choices=["ask","auto","yolo"],default="ask",help="Explicit first-setup mode; defaults to Always ask")
    s=sub.add_parser("init",help="Initialize from a terminal (start gives a browser setup)");s.add_argument("--mode",choices=["ask","auto","yolo"],default="ask");s.add_argument("--unattended",action="store_true",help="Store a local unlock file; readable by this OS user")
    s=sub.add_parser("connect",help="Guided Tailscale sign-in and private HTTPS");s.add_argument("--port",type=int,default=PORT);s.add_argument("--no-open",action="store_true")
    s=sub.add_parser("pair",help="Pair this agent with an owner-generated code");s.add_argument("url");s.add_argument("--name",default="My agent")
    sub.add_parser("keys",help="List names without revealing values")
    s=sub.add_parser("request",help="Make an authenticated API request");s.add_argument("key");s.add_argument("path");s.add_argument("--method",default="GET");s.add_argument("--purpose",required=True);s.add_argument("--body-file",type=Path)
    s=sub.add_parser("run",help="Request a raw key and pass it to one trusted child process");s.add_argument("key");s.add_argument("variable");s.add_argument("--purpose",required=True);s.add_argument("argv",nargs=argparse.REMAINDER)
    s=sub.add_parser("capture",help="Open the owner’s named clipboard capture form");s.add_argument("name");s.add_argument("--origin",default="");s.add_argument("--url",default=f"http://127.0.0.1:{PORT}")
    sub.add_parser("mcp",help="Run the MCP stdio server for a paired agent")
    s=sub.add_parser("install-skill",help="Install the bundled skill for Codex or another agent");s.add_argument("--directory",type=Path,default=Path.home()/".codex/skills/latchlane")
    sub.add_parser("owner",help="Open the local owner console; unattended sessions require a host restart after ticket use")
    sub.add_parser("doctor",help="Check local readiness without reading key values")
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
        elif args.command=="capture":
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}",args.name): raise ValueError("Use a lowercase key name.")
            url=broker_url(args.url)+"/?"+urlencode({"capture":args.name,"origin":args.origin})
            webbrowser.open(url);print("Capture form opened. Sign in, confirm the destination, then choose Watch next copy. Do not paste secrets into chat.")
        elif args.command=="owner":
            ticket=data_dir()/"owner-ticket.local.json"
            if ticket.exists():
                webbrowser.open(json.loads(private_read(ticket))["url"])
                print("Owner window opened. If the one-use session expired, restart the host to issue a fresh one.")
            else:
                webbrowser.open(f"http://127.0.0.1:{PORT}/")
        elif args.command=="mcp": mcp()
        elif args.command=="install-skill":
            source=Path(__file__).with_name("SKILL.md")
            if not source.exists(): source=Path(__file__).parents[2]/"skills/latchlane/SKILL.md"
            dest=args.directory/"SKILL.md"
            if dest.exists(): raise ValueError("Skill exists. Review and update it deliberately.")
            args.directory.mkdir(parents=True,exist_ok=True);dest.write_text(source.read_text());print("Latchlane skill installed.")
        else:
            root=data_dir();print(json.dumps({"vault_exists":(root/"store.vault").exists(),"agent_paired":(root/"agent.local.json").exists(),"unattended":(root/"unattended.key").exists(),"tailscale_installed":bool(tailscale_bin()),"tailscale_connected":tail_status().get("BackendState")=="Running"},indent=2))
    except (ValueError,VaultError,Timeout,FileNotFoundError) as e:
        print(str(e) if not isinstance(e,FileNotFoundError) else "Not set up yet. Run latchlane start or latchlane pair.",file=sys.stderr);sys.exit(1)
    except KeyboardInterrupt: pass
    except Exception:
        print("Operation failed. No credentials were printed. Check the owner console and doctor.",file=sys.stderr);sys.exit(1)
