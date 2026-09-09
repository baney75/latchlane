"""Local owner console and authenticated agent broker."""
import copy
from contextlib import contextmanager
import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from .vault import Vault, VaultError
from .network import validate_origin, perform, NetworkError
from . import __version__

STATIC = Path(__file__).parent / "static"
SESSION_SECONDS = {"day": 24 * 3600, "remember": 30 * 24 * 3600}
MAX_OWNER_SESSIONS = 20

class Password(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    session_mode: Literal["day", "remember"] = "day"

class KeyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    value: str = Field(min_length=1, max_length=16384)
    origin: str = Field(max_length=300)
    kind: Literal["api_key", "password"] = "api_key"
    username: str = Field(default="", max_length=320)
    header: str = "Authorization"
    prefix: str = "Bearer "
    safe_paths: list[str] = Field(default_factory=list, max_length=30)

class KeyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: str = Field(max_length=300)
    header: str = "Authorization"
    prefix: str = "Bearer "
    safe_paths: list[str] = Field(default_factory=list, max_length=30)
    value: str | None = Field(default=None, max_length=16384)
    # Omitting kind preserves an existing password record. This makes older edit
    # forms safe while allowing an explicit type change by the owner.
    kind: Literal["api_key", "password"] | None = None
    username: str | None = Field(default=None, max_length=320)

class KeyBatch(BaseModel):
    items: list[KeyInput] = Field(min_length=1, max_length=20)

class CollectionDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    kind: Literal["api_key", "password"] = "api_key"
    origin: str = Field(max_length=300)
    header: str = "Authorization"
    prefix: str = "Bearer "

class CollectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    purpose: str = Field(min_length=1, max_length=300)
    items: list[CollectionDescriptor] = Field(min_length=1, max_length=20)

class CollectionCompleteItem(BaseModel):
    """Owner-only value input. Collection completion deliberately has no routes."""
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    value: str = Field(min_length=1, max_length=16384)
    origin: str = Field(max_length=300)
    kind: Literal["api_key", "password"] = "api_key"
    username: str = Field(default="", max_length=320)
    header: str = "Authorization"
    prefix: str = "Bearer "

class CollectionComplete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[CollectionCompleteItem] = Field(min_length=1, max_length=20)

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
    if not all(32 < ord(c) < 127 for c in path):
        return False

    # HTTP servers normalize only the path. A fixed number of decoding passes
    # catches nested dot encodings without repeatedly decoding attacker input.
    candidate = urlsplit(path).path
    for _ in range(2):
        if _unsafe_path_segments(candidate):
            return False
        candidate = unquote(candidate)
    return not _unsafe_path_segments(candidate) and candidate == unquote(candidate)


def _unsafe_path_segments(path):
    if "\\" in path or any(segment in (".", "..") for segment in path.split("/")):
        return True
    # Encoded separators can create dot segments after provider-side decoding.
    lowered = path.lower()
    return "%2f" in lowered or "%5c" in lowered


def create_app(directory: Path, port=9473, hosts=(), bootstrap=None, initial_mode="ask"):
    if initial_mode not in ("ask", "auto", "yolo"): raise ValueError("Invalid initial mode")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.vault = Vault(directory)
    app.state.bootstrap = bootstrap or secrets.token_urlsafe(32)
    app.state.sessions = {}
    app.state.pending = {}
    # Collections are deliberately process-local metadata. Values are only ever
    # written to the encrypted vault by the owner completion endpoint.
    app.state.collections = {}
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
                     copy.deepcopy(app.state.pending), copy.deepcopy(app.state.collections), dict(app.state.invites),
                     dict(app.state.sessions), app.state.bootstrap)
            try:
                yield
            except Exception:
                (v.data, v.key, v.salt, app.state.pending, app.state.collections, app.state.invites,
                 app.state.sessions, app.state.bootstrap) = saved
                raise

    def discard_owner_ticket():
        try: (directory / "owner-ticket.local.json").unlink(missing_ok=True)
        except OSError: pass  # Revoked token is harmless; cleanup is best effort.

    def prune_sessions(now=None, keep=None):
        with app.state.lock:
            now = time.time() if now is None else now
            app.state.sessions = {
                ident: session for ident, session in app.state.sessions.items()
                if isinstance(session, dict) and session.get("expires", 0) > now
            }
            if len(app.state.sessions) > MAX_OWNER_SESSIONS:
                for ident in sorted(app.state.sessions, key=lambda item: app.state.sessions[item]["expires"]):
                    if ident != keep:
                        del app.state.sessions[ident]
                        if len(app.state.sessions) == MAX_OWNER_SESSIONS:
                            break

    def clear_owner_cookie(response, request):
        response.delete_cookie("latchlane_owner", httponly=True, samesite="strict", secure=request.url.scheme == "https")

    @app.middleware("http")
    async def boundary(request, call_next):
        prune_sessions()
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

    def normalized_key(kind, origin, header, prefix, safe_paths):
        """Validate and return canonical broker metadata without touching a value."""
        try: origin = validate_origin(origin)
        except ValueError as e: raise HTTPException(422, str(e))
        if kind == "password":
            # A website password must only ever move through the raw lease path.
            if safe_paths:
                raise HTTPException(422, "Password credentials cannot have trusted HTTP paths.")
            return {"kind": "password", "origin": origin, "header": "Authorization", "prefix": "", "safe_paths": []}
        if header not in ("Authorization", "X-API-Key", "API-KEY", "api-key", "x-goog-api-key"):
            raise HTTPException(422, "Unsupported authentication header.")
        if prefix not in ("", "Bearer ", "Basic "):
            raise HTTPException(422, "Unsupported prefix.")
        if any(not valid_path(path) or "?" in path or "%" in path for path in safe_paths):
            raise HTTPException(422, "Auto-approve paths must be exact paths without query strings or escapes.")
        return {"kind": "api_key", "origin": origin, "header": header, "prefix": prefix, "safe_paths": safe_paths}

    def collection_descriptor(item):
        metadata = normalized_key(item.kind, item.origin, item.header, item.prefix, [])
        return {"name": item.name, **metadata}

    def prune_collections(now=None):
        """Keep expiry semantics while bounding local metadata after long uptime."""
        now = time.time() if now is None else now
        for record in app.state.collections.values():
            if record["status"] == "pending" and record["expires"] <= now:
                record["status"] = "expired"
        # Status records exist only to give the requesting client an honest 410.
        # Retain a bounded, recent tombstone set rather than unbounded history.
        if len(app.state.collections) > 200:
            ordered = sorted(app.state.collections, key=lambda ident: app.state.collections[ident]["expires"])
            for ident in ordered[:len(app.state.collections) - 200]:
                del app.state.collections[ident]

    def owner(request):
        with app.state.lock:
            token = request.cookies.get("latchlane_owner", "")
            session_data = app.state.sessions.get(digest(token))
            if not session_data or session_data["expires"] < time.time():
                raise HTTPException(401, "Sign in to the owner console.")
            require_unlocked()
            return session_data

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

    def session(request, mode="day"):
        with app.state.lock:
            now = time.time()
            prune_sessions(now)
            token = secrets.token_urlsafe(32)
            expiry = now + SESSION_SECONDS[mode]
            ident = digest(token)
            app.state.sessions[ident] = {"expires": expiry, "mode": mode}
            prune_sessions(now, keep=ident)
        response = JSONResponse({"ok": True})
        response.set_cookie("latchlane_owner", token, httponly=True, samesite="strict", secure=request.url.scheme == "https", max_age=SESSION_SECONDS[mode])
        return response

    def key_value(value, kind="api_key"):
        if kind == "api_key" and any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise HTTPException(422, "Key must contain printable ASCII only.")

    def stored_key(value, item, metadata=None):
        metadata = metadata or normalized_key(item.kind, item.origin, item.header, item.prefix, item.safe_paths)
        key_value(value, metadata["kind"])
        return {"value": value, "username": item.username, **metadata}

    @app.get("/")
    def index(): return FileResponse(STATIC / "index.html")

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in ("app.js", "credentials.js", "app.css", "mark.svg", "offline.css"): raise HTTPException(404)
        return FileResponse(STATIC / name)

    @app.get("/manifest.webmanifest")
    def manifest():
        return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")

    @app.get("/sw.js")
    def service_worker():
        response = FileResponse(STATIC / "sw.js", media_type="application/javascript")
        response.headers["Service-Worker-Allowed"] = "/"
        return response

    @app.get("/offline.html")
    def offline():
        return FileResponse(STATIC / "offline.html", media_type="text/html")

    @app.get("/assets/icons/{name}")
    def icon(name: str):
        if name not in ("mark-192.png", "mark-512.png"): raise HTTPException(404)
        return FileResponse(STATIC / "icons" / name, media_type="image/png")

    @app.get("/api/status")
    def status(): return {"initialized": v.path.exists(), "locked": v.data is None, "version": __version__, "initial_mode": initial_mode}

    @app.post("/api/init")
    def initialize(body: Password, request: Request):
        with transaction():
            if not hmac.compare_digest(request.headers.get("x-setup-token", ""), app.state.bootstrap):
                raise HTTPException(403, "Open the setup window from latchlane start.")
            v.initialize(body.password, mode=initial_mode)
            app.state.bootstrap = secrets.token_urlsafe(32)
            discard_owner_ticket()
            return session(request, body.session_mode)

    @app.post("/api/login")
    def login(body: Password, request: Request):
        with transaction():
            now = time.time()
            app.state.login_attempts = [t for t in app.state.login_attempts if t > now - 60]
            if len(app.state.login_attempts) >= 5: raise HTTPException(429, "Wait a minute before trying again.")
            app.state.login_attempts.append(now)
            v.unlock(body.password)
            return session(request, body.session_mode)

    @app.post("/api/local-session")
    def local_session(request: Request):
        with transaction():
            require_unlocked()
            if not hmac.compare_digest(request.headers.get("x-setup-token", ""), app.state.bootstrap):
                raise HTTPException(403, "Open the owner window locally.")
            app.state.bootstrap = secrets.token_urlsafe(32)
            discard_owner_ticket()
            return session(request)

    @app.post("/api/logout")
    def logout(request: Request):
        with app.state.lock:
            app.state.sessions.pop(digest(request.cookies.get("latchlane_owner", "")), None)
        response = JSONResponse({"ok": True})
        clear_owner_cookie(response, request)
        return response

    @app.post("/api/lock")
    def lock(request: Request):
        with transaction():
            owner(request)
            v.lock(); app.state.sessions.clear(); app.state.pending.clear(); app.state.collections.clear(); app.state.invites.clear()
            response = JSONResponse({"ok": True})
            clear_owner_cookie(response, request)
            return response

    @app.get("/api/owner")
    def dashboard(request: Request):
        with transaction():
            session_data = owner(request)
            clean = [{k: val for k, val in item.items() if k != "value"} | {"name": name} for name, item in v.data["keys"].items()]
            pending = [{"id": rid, "operation": r["op"], "agent": v.data["clients"].get(r["client"], {}).get("name", "revoked"), "expires": r["expires"]} for rid, r in app.state.pending.items() if r["status"] == "pending" and r["expires"] > time.time()]
            prune_collections()
            collections = [
                {"id": ident, "agent": v.data["clients"].get(record["client"], {}).get("name", "revoked"), "purpose": record["purpose"], "items": record["items"], "expires_at": record["expires"]}
                for ident, record in app.state.collections.items()
                if record["status"] == "pending" and record["expires"] > time.time()
            ]
            return {"mode": v.data["mode"], "keys": clean, "clients": [{"id": ident, "name": data["name"]} for ident, data in v.data["clients"].items()], "pending": pending, "collections": collections, "audit": v.data["audit"][-20:][::-1], "revision": v.data["revision"], "session_expires": session_data["expires"], "session_mode": session_data["mode"]}

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
            v.data["keys"][body.name] = stored_key(body.value, body)
            audit("key:added", body.name); v.save()
            return {"ok": True, "name": body.name}

    @app.post("/api/keys/batch")
    def add_keys_batch(body: KeyBatch, request: Request):
        with transaction():
            owner(request)
            names = [item.name for item in body.items]
            if len(names) != len(set(names)) or any(name in v.data["keys"] for name in names):
                raise HTTPException(409, "Names must be new and unique.")
            if len(v.data["keys"]) + len(body.items) > 200:
                raise HTTPException(409, "Vault key limit reached.")
            # Validate every secret and destination before the first mutation.
            prepared = [(item.name, stored_key(item.value, item)) for item in body.items]
            for name, record in prepared:
                v.data["keys"][name] = record
                audit("key:added", name)
            v.save()
            return {"ok": True, "names": names}

    @app.patch("/api/keys/{name}")
    def update_key(name: str, body: KeyUpdate, request: Request):
        with transaction():
            owner(request)
            current = v.data["keys"].get(name)
            if not current: raise HTTPException(404)
            kind = body.kind if body.kind is not None else current.get("kind", "api_key")
            username = body.username if body.username is not None else current.get("username", "")
            metadata = normalized_key(kind, body.origin, body.header, body.prefix, body.safe_paths)
            value = current["value"] if body.value in (None, "") else body.value
            # Validate the chosen final value even when an edit retains it. A
            # password can contain Unicode, while an API key cannot.
            key_value(value, kind)
            v.data["keys"][name] = {"value": value, "username": username, **metadata}
            app.state.pending = {rid: pending for rid, pending in app.state.pending.items() if pending["op"]["key"] != name}
            audit("key:updated", name); v.save()
            return {"ok": True, "name": name}

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
            app.state.collections = {rid:r for rid,r in app.state.collections.items() if r["client"] != ident}
            audit("agent:revoked"); v.save()
            return {"ok": True}

    @app.post("/api/collections")
    def create_collection(body: CollectionCreate, request: Request):
        with transaction():
            ident = client(request)
            prune_collections()
            names = [item.name for item in body.items]
            if len(names) != len(set(names)) or any(name in v.data["keys"] for name in names):
                raise HTTPException(409, "Credential names must be new and unique.")
            active = [record for record in app.state.collections.values() if record["status"] == "pending" and record["expires"] > time.time()]
            if len(active) >= 20:
                raise HTTPException(429, "Too many active collection requests.")
            if sum(record["client"] == ident for record in active) >= 3:
                raise HTTPException(429, "This agent already has three active collection requests.")
            # Collection descriptors intentionally cannot supply values, routes,
            # usernames, or any unknown fields. Normalize all before storing state.
            items = [collection_descriptor(item) for item in body.items]
            collection_id = secrets.token_urlsafe(18)
            now = time.time()
            app.state.collections[collection_id] = {"client": ident, "purpose": body.purpose, "items": items, "expires": now + 900, "status": "pending"}
            audit("collection:requested", agent=v.data["clients"][ident]["name"])
            v.save()
            return {"id": collection_id, "status": "pending", "expires_at": now + 900, "owner_path": "/?collection=" + collection_id}

    def collection_for_client(collection_id, ident):
        prune_collections()
        record = app.state.collections.get(collection_id)
        if not record or record["client"] != ident:
            raise HTTPException(404, "Collection not found.")
        if record["status"] == "expired" or record["expires"] <= time.time():
            raise HTTPException(410, "Collection expired.")
        return record

    @app.get("/api/collections/{collection_id}")
    def collection_status(collection_id: str, request: Request):
        with transaction():
            ident = client(request)
            record = collection_for_client(collection_id, ident)
            # Never expose usernames or values to the requesting agent.
            return {"id": collection_id, "status": record["status"], "names": [item["name"] for item in record["items"]], "expires_at": record["expires"]}

    @app.get("/api/owner/collections/{collection_id}")
    def owner_collection(collection_id: str, request: Request):
        with transaction():
            owner(request)
            prune_collections()
            record = app.state.collections.get(collection_id)
            if not record: raise HTTPException(404, "Collection not found.")
            if record["status"] == "expired" or record["expires"] <= time.time(): raise HTTPException(410, "Collection expired.")
            if record["status"] != "pending": raise HTTPException(409, "Collection is no longer pending.")
            return {"id": collection_id, "agent": v.data["clients"].get(record["client"], {}).get("name", "revoked"), "purpose": record["purpose"], "items": record["items"], "expires_at": record["expires"]}

    @app.post("/api/owner/collections/{collection_id}/complete")
    def complete_collection(collection_id: str, body: CollectionComplete, request: Request):
        with transaction():
            owner(request)
            prune_collections()
            record = app.state.collections.get(collection_id)
            if not record or record["status"] != "pending" or record["expires"] <= time.time():
                raise HTTPException(409, "Collection expired or already completed.")
            if len(v.data["keys"]) + len(body.items) > 200:
                raise HTTPException(409, "Vault key limit reached.")
            submitted = [collection_descriptor(item) for item in body.items]
            if submitted != record["items"]:
                raise HTTPException(422, "Credentials must exactly match the requested names and destinations.")
            names = [item.name for item in body.items]
            if len(names) != len(set(names)) or any(name in v.data["keys"] for name in names):
                raise HTTPException(409, "Credential names must be new and unique.")
            prepared = [(item.name, stored_key(item.value, item, descriptor)) for item, descriptor in zip(body.items, submitted)]
            for name, key in prepared:
                v.data["keys"][name] = key
                audit("key:added", name)
            record["status"] = "completed"
            audit("collection:completed", agent=v.data["clients"].get(record["client"], {}).get("name", "revoked"))
            v.save()
            return {"ok": True, "id": collection_id, "status": "completed", "names": names}

    @app.post("/api/owner/collections/{collection_id}/cancel")
    def cancel_collection(collection_id: str, request: Request):
        with transaction():
            owner(request)
            prune_collections()
            record = app.state.collections.get(collection_id)
            if not record or record["status"] != "pending" or record["expires"] <= time.time():
                raise HTTPException(409, "Collection expired or already decided.")
            record["status"] = "cancelled"
            audit("collection:cancelled", agent=v.data["clients"].get(record["client"], {}).get("name", "revoked"))
            v.save()
            return {"ok": True, "id": collection_id, "status": "cancelled"}

    @app.get("/api/keys")
    def names(request: Request):
        with transaction():
            client(request)
            return {"keys": [{"name": n, "origin": d["origin"], "kind": d.get("kind", "api_key")} for n,d in v.data["keys"].items()], "mode": v.data["mode"], "revision": v.data["revision"]}

    @app.post("/api/requests")
    def request_use(body: Operation, request: Request):
        with transaction():
            ident = client(request)
            key = v.data["keys"].get(body.key)
            if not key: raise HTTPException(404, "Key not found.")
            if body.kind not in ("http", "lease"): raise HTTPException(422, "Unsupported operation.")
            if key.get("kind", "api_key") == "password" and body.kind != "lease":
                raise HTTPException(422, "Password credentials are lease-only and cannot be sent as HTTP headers.")
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
