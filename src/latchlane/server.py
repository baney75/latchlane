"""Local owner console and authenticated agent broker."""
import copy
from contextlib import contextmanager
import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from .vault import Vault, VaultError
from .network import validate_origin, perform, NetworkError

STATIC = Path(__file__).parent / "static"

class Password(BaseModel):
    password: str = Field(min_length=1, max_length=1024)

class KeyInput(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    value: str = Field(min_length=1, max_length=16384)
    origin: str = Field(max_length=300)
    header: str = "Authorization"
    prefix: str = "Bearer "
    safe_paths: list[str] = Field(default_factory=list, max_length=30)

class Operation(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    kind: str = "http"
    method: str = "GET"
    path: str = Field(default="/", max_length=4096)
    body: str = Field(default="", max_length=65536)
    purpose: str = Field(min_length=1, max_length=300)

class Mode(BaseModel):
    mode: str

class PairInput(BaseModel):
    code: str = Field(min_length=20, max_length=100)
    name: str = Field(min_length=1, max_length=60)

class Decision(BaseModel):
    approve: bool


def digest(value): return hashlib.sha256(value.encode()).hexdigest()


def valid_path(path):
    if not path.startswith("/") or path.startswith("//") or "\\" in path or "#" in path:
        return False
    return all(32 < ord(c) < 127 for c in path)


def create_app(directory: Path, port=9473, hosts=(), bootstrap=None, initial_mode="ask"):
    if initial_mode not in ("ask", "auto", "yolo"): raise ValueError("Invalid initial mode")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.vault = Vault(directory)
    app.state.bootstrap = bootstrap or secrets.token_urlsafe(32)
    app.state.sessions = {}
    app.state.pending = {}
    app.state.invites = {}
    app.state.login_attempts = []
    app.state.lock = threading.RLock()
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", *hosts}
    v = app.state.vault

    @contextmanager
    def transaction():
        # Preserve the pre-operation authorization state if persistence fails.
        # Login attempt counters deliberately survive failed authentication.
        with app.state.lock:
            saved = (copy.deepcopy(v.data), v.key, v.salt,
                     copy.deepcopy(app.state.pending), dict(app.state.invites),
                     dict(app.state.sessions), app.state.bootstrap)
            try:
                yield
            except Exception:
                (v.data, v.key, v.salt, app.state.pending, app.state.invites,
                 app.state.sessions, app.state.bootstrap) = saved
                raise

    def discard_owner_ticket():
        try: (directory / "owner-ticket.local.json").unlink(missing_ok=True)
        except OSError: pass  # Revoked token is harmless; cleanup is best effort.

    @app.middleware("http")
    async def boundary(request, call_next):
        if request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"detail": "Unrecognized host."}, status_code=403)
        origin = request.headers.get("origin")
        if origin and (urlsplit(origin).netloc not in allowed_hosts or urlsplit(origin).scheme not in ("http", "https")):
            return JSONResponse({"detail": "Cross-origin requests are blocked."}, status_code=403)
        if request.method not in ("GET", "HEAD") and request.headers.get("x-latchlane") != "1":
            return JSONResponse({"detail": "Missing request guard."}, status_code=403)
        # Streaming size check prevents unbounded JSON bodies, even without Content-Length.
        if request.method not in ("GET", "HEAD"):
            body = bytearray()
            async for part in request.stream():
                body.extend(part)
                if len(body) > 100000:
                    return JSONResponse({"detail": "Request too large."}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", "Permissions-Policy": "clipboard-read=(self), clipboard-write=(self), camera=(), microphone=()"})
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default includes rejected input, which may be a secret.
        return JSONResponse({"detail": "Check the field formats and sizes."}, status_code=422)

    @app.exception_handler(VaultError)
    async def vault_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    def require_unlocked():
        if v.data is None: raise HTTPException(423, "Vault is locked. Open the owner console.")

    def owner(request):
        token = request.cookies.get("latchlane_owner", "")
        if app.state.sessions.get(digest(token), 0) < time.time():
            raise HTTPException(401, "Sign in to the owner console.")
        require_unlocked()

    def client(request):
        require_unlocked()
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "): raise HTTPException(401, "Pair this agent first.")
        ident = digest(auth[7:])
        if ident not in v.data["clients"]: raise HTTPException(401, "Agent is not paired or was revoked.")
        return ident

    def audit(event, name="", agent=""):
        v.data["audit"].append({"time": int(time.time()), "event": event, "key": name, "agent": agent})
        v.data["audit"] = v.data["audit"][-300:]

    def session(request):
        token = secrets.token_urlsafe(32)
        app.state.sessions[digest(token)] = time.time() + 8 * 3600
        response = JSONResponse({"ok": True})
        response.set_cookie("latchlane_owner", token, httponly=True, samesite="strict", secure=request.url.scheme == "https", max_age=8*3600)
        return response

    @app.get("/")
    def index(): return FileResponse(STATIC / "index.html")

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in ("app.js", "app.css", "mark.svg"): raise HTTPException(404)
        return FileResponse(STATIC / name)

    @app.get("/api/status")
    def status(): return {"initialized": v.path.exists(), "locked": v.data is None, "version": "0.1.1", "initial_mode": initial_mode}

    @app.post("/api/init")
    def initialize(body: Password, request: Request):
        with transaction():
            if not hmac.compare_digest(request.headers.get("x-setup-token", ""), app.state.bootstrap):
                raise HTTPException(403, "Open the setup window from latchlane start.")
            v.initialize(body.password, mode=initial_mode)
            app.state.bootstrap = secrets.token_urlsafe(32)
            discard_owner_ticket()
            return session(request)

    @app.post("/api/login")
    def login(body: Password, request: Request):
        with transaction():
            now = time.time()
            app.state.login_attempts = [t for t in app.state.login_attempts if t > now - 60]
            if len(app.state.login_attempts) >= 5: raise HTTPException(429, "Wait a minute before trying again.")
            app.state.login_attempts.append(now)
            v.unlock(body.password)
            return session(request)

    @app.post("/api/local-session")
    def local_session(request: Request):
        with transaction():
            require_unlocked()
            if not hmac.compare_digest(request.headers.get("x-setup-token", ""), app.state.bootstrap):
                raise HTTPException(403, "Open the owner window locally.")
            app.state.bootstrap = secrets.token_urlsafe(32)
            discard_owner_ticket()
            return session(request)

    @app.post("/api/lock")
    def lock(request: Request):
        with transaction():
            owner(request)
            v.lock(); app.state.sessions.clear(); app.state.pending.clear(); app.state.invites.clear()
            return {"ok": True}

    @app.get("/api/owner")
    def dashboard(request: Request):
        with transaction():
            owner(request)
            clean = [{k: val for k, val in item.items() if k != "value"} | {"name": name} for name, item in v.data["keys"].items()]
            pending = [{"id": rid, "operation": r["op"], "agent": v.data["clients"].get(r["client"], {}).get("name", "revoked"), "expires": r["expires"]} for rid, r in app.state.pending.items() if r["status"] == "pending" and r["expires"] > time.time()]
            return {"mode": v.data["mode"], "keys": clean, "clients": [{"id": ident, "name": data["name"]} for ident, data in v.data["clients"].items()], "pending": pending, "audit": v.data["audit"][-20:][::-1], "revision": v.data["revision"]}

    @app.post("/api/mode")
    def mode(body: Mode, request: Request):
        with transaction():
            owner(request)
            if body.mode not in ("ask", "auto", "yolo"): raise HTTPException(422, "Unknown mode.")
            v.data["mode"] = body.mode
            # Decisions are tied to the policy at request time; changing mode cancels them.
            app.state.pending.clear()
            audit("mode:" + body.mode); v.save()
            return {"ok": True}

    @app.post("/api/keys")
    def add_key(body: KeyInput, request: Request):
        with transaction():
            owner(request)
            if body.name in v.data["keys"]: raise HTTPException(409, "Name exists. Use a new name to rotate safely.")
            if len(v.data["keys"]) >= 200: raise HTTPException(409, "Vault key limit reached.")
            try: origin = validate_origin(body.origin)
            except ValueError as e: raise HTTPException(422, str(e))
            if body.header not in ("Authorization", "X-API-Key", "API-KEY", "api-key", "x-goog-api-key"):
                raise HTTPException(422, "Unsupported authentication header.")
            if body.prefix not in ("", "Bearer ", "Basic "): raise HTTPException(422, "Unsupported prefix.")
            if any(ord(c) < 32 or ord(c) > 126 for c in body.value): raise HTTPException(422, "Key must contain printable ASCII only.")
            if any(not valid_path(p) or "?" in p or "%" in p for p in body.safe_paths):
                raise HTTPException(422, "Auto-approve paths must be exact paths without query strings or escapes.")
            v.data["keys"][body.name] = {"value": body.value, "origin": origin, "header": body.header, "prefix": body.prefix, "safe_paths": body.safe_paths}
            audit("key:added", body.name); v.save()
            return {"ok": True, "name": body.name}

    @app.delete("/api/keys/{name}")
    def delete_key(name: str, request: Request):
        with transaction():
            owner(request)
            if name not in v.data["keys"]: raise HTTPException(404)
            del v.data["keys"][name]
            app.state.pending = {rid:r for rid,r in app.state.pending.items() if r["op"]["key"] != name}
            audit("key:removed", name); v.save()
            return {"ok": True}

    @app.post("/api/invite")
    def invite(request: Request):
        with transaction():
            owner(request)
            code = secrets.token_urlsafe(24)
            app.state.invites = {digest(code): time.time() + 300}
            return {"code": code, "expires_in": 300}

    @app.post("/api/pair")
    def pair(body: PairInput):
        with transaction():
            require_unlocked()
            if app.state.invites.pop(digest(body.code), 0) < time.time(): raise HTTPException(403, "Pairing code expired or invalid.")
            if len(v.data["clients"]) >= 100: raise HTTPException(409, "Device limit reached.")
            token = secrets.token_urlsafe(32)
            v.data["clients"][digest(token)] = {"name": body.name}
            audit("agent:paired", agent=body.name); v.save()
            return {"token": token}

    @app.delete("/api/clients/{ident}")
    def revoke(ident: str, request: Request):
        with transaction():
            owner(request)
            v.data["clients"].pop(ident, None)
            app.state.pending = {rid:r for rid,r in app.state.pending.items() if r["client"] != ident}
            audit("agent:revoked"); v.save()
            return {"ok": True}

    @app.get("/api/keys")
    def names(request: Request):
        with transaction():
            client(request)
            return {"keys": [{"name": n, "origin": d["origin"]} for n,d in v.data["keys"].items()], "mode": v.data["mode"], "revision": v.data["revision"]}

    @app.post("/api/requests")
    def request_use(body: Operation, request: Request):
        with transaction():
            ident = client(request)
            key = v.data["keys"].get(body.key)
            if not key: raise HTTPException(404, "Key not found.")
            if body.kind not in ("http", "lease"): raise HTTPException(422, "Unsupported operation.")
            if body.method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE") or not valid_path(body.path):
                raise HTTPException(422, "Invalid method or path.")
            if body.kind == "lease" and (body.body or body.path != "/" or body.method != "GET"):
                raise HTTPException(422, "Lease requests contain only a key and purpose.")
            now = time.time()
            app.state.pending = {rid:r for rid,r in app.state.pending.items() if r["expires"] > now}
            if len(app.state.pending) >= 100: raise HTTPException(429, "Too many requests. Wait for pending requests to expire.")
            safe = body.kind == "http" and body.method == "GET" and not body.body and body.path in key["safe_paths"] and "?" not in body.path and "%" not in body.path
            approved = v.data["mode"] == "yolo" or (v.data["mode"] == "auto" and safe)
            rid = secrets.token_urlsafe(18)
            app.state.pending[rid] = {"client": ident, "op": body.model_dump(), "expires": now + 300, "status": "approved" if approved else "pending"}
            audit("request:auto" if approved else "request:pending", body.key, v.data["clients"][ident]["name"]); v.save()
            return {"id": rid, "status": app.state.pending[rid]["status"], "expires_in": 300}

    @app.post("/api/requests/{rid}/decision")
    def decide(rid: str, body: Decision, request: Request):
        with transaction():
            owner(request)
            r = app.state.pending.get(rid)
            if not r or r["expires"] < time.time() or r["status"] != "pending": raise HTTPException(409, "Request expired or already decided.")
            r["status"] = "approved" if body.approve else "denied"
            audit("request:" + r["status"], r["op"]["key"]); v.save()
            return {"ok": True}

    @app.post("/api/requests/{rid}/consume")
    def consume(rid: str, request: Request):
        with transaction():
            ident = client(request)
            r = app.state.pending.get(rid)
            if not r or r["client"] != ident: raise HTTPException(404, "Request not found.")
            if r["expires"] < time.time(): raise HTTPException(410, "Request expired.")
            if r["status"] == "pending": return JSONResponse({"status": "pending"}, status_code=202)
            if r["status"] != "approved": raise HTTPException(403, "Request denied or already consumed.")
            key = dict(v.data["keys"][r["op"]["key"]])
            r["status"] = "consumed"
            audit("key:used", r["op"]["key"], v.data["clients"][ident]["name"]); v.save()
            if r["op"]["kind"] == "lease":
                return {"value": key["value"]}
        try: return perform(key, r["op"])
        except NetworkError as e: raise HTTPException(502, str(e))

    return app
