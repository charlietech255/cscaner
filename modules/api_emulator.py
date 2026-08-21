#!/usr/bin/env python3
"""Real local API emulator for authorized testing and contract validation.

This is not a mock route table. It runs as a real HTTP service with:
- valid JSON request/response handling
- bearer-token auth
- persistent state on disk
- realistic validation and error responses
- a built-in scan function that exercises the API contract
"""

import json
import os
import secrets
from datetime import datetime, timezone
from threading import RLock
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 8081
DEFAULT_HOST = "127.0.0.1"
STATE_FILE = Path(__file__).resolve().parents[1] / "api_emulator_state.json"


class ApiEmulatorState:
    def __init__(self, state_file: str | Path = STATE_FILE):
        self.state_file = Path(state_file)
        self.users = []
        self.tokens = {}
        self._lock = RLock()
        self._load()

    def _load(self):
        if not self.state_file.exists():
            self._seed_default_users()
            self._save()
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.users = data.get("users", [])
            self.tokens = data.get("tokens", {})
            if not self.users:
                self._seed_default_users()
                self._save()
        except Exception:
            self._seed_default_users()
            self._save()

    def _seed_default_users(self):
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.users = [
            {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin", "created_at": now},
            {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "member", "created_at": now},
        ]
        self.tokens = {}

    def _save(self):
        payload = {"users": self.users, "tokens": self.tokens}
        temp_file = self.state_file.with_name(f".{self.state_file.name}.tmp")
        with open(temp_file, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_file, self.state_file)

    def next_user_id(self):
        if not self.users:
            return 1
        return max(user["id"] for user in self.users) + 1

    def login(self, username: str, password: str):
        valid = (username == "admin" and password == "letmein") or (username == "alice" and password == "secret")
        if not valid:
            return None
        token = f"token-{secrets.token_urlsafe(32)}"
        with self._lock:
            self.tokens[token] = username
            self._save()
        return token

    def require_token(self, token: str | None):
        if not token or token not in self.tokens:
            return False
        return True

    def list_users(self, page=1, limit=10):
        start = (page - 1) * limit
        end = start + limit
        return self.users[start:end]

    def get_user(self, user_id):
        for user in self.users:
            if user["id"] == user_id:
                return user
        return None

    def create_user(self, data):
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        if not data.get("name") or not data.get("email"):
            raise ValueError("name and email are required")
        if "@" not in data["email"]:
            raise ValueError("email must be a valid email address")
        user = {
            "id": self.next_user_id(),
            "name": data["name"],
            "email": data["email"],
            "role": data.get("role", "member"),
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        with self._lock:
            self.users.append(user)
            self._save()
        return user

    def update_user(self, user_id, data):
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        user = self.get_user(user_id)
        if user is None:
            return None
        for key in ("name", "email", "role"):
            if key in data:
                user[key] = data[key]
        self._save()
        return user

    def delete_user(self, user_id):
        user = self.get_user(user_id)
        if user is None:
            return False
        self.users = [u for u in self.users if u["id"] != user_id]
        self._save()
        return True


class ApiEmulatorHandler(BaseHTTPRequestHandler):
    server_version = "CscanApiEmulator/1.0"

    @property
    def state(self):
        return self.server.state

    def log_message(self, format, *args):
        return

    def send_json(self, status_code, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return {}
        raw = self.rfile.read(content_length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("request body must be valid JSON") from exc

    def get_bearer_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        return None

    def handle_route(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if self.command == "GET" and path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok", "service": "cscan-api-emulator", "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")})
            return

        if self.command == "POST" and path == "/auth/login":
            try:
                data = self.read_json()
            except ValueError as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            username = str(data.get("username", "")).strip()
            password = str(data.get("password", "")).strip()
            token = self.state.login(username, password)
            if token is None:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
                return
            self.send_json(HTTPStatus.OK, {"token": token, "user": username})
            return

        if self.command == "GET" and path == "/api/v1/metrics":
            token = self.get_bearer_token()
            if not self.state.require_token(token):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid or missing token"})
                return
            self.send_json(HTTPStatus.OK, {"total_users": len(self.state.users), "active_tokens": len(self.state.tokens)})
            return

        if self.command == "GET" and path == "/api/v1/users":
            token = self.get_bearer_token()
            if not self.state.require_token(token):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid or missing token"})
                return
            page = int(query.get("page", ["1"])[0])
            limit = int(query.get("limit", ["10"])[0])
            page = max(1, page)
            limit = max(1, min(limit, 100))
            users = self.state.list_users(page=page, limit=limit)
            self.send_json(HTTPStatus.OK, {"page": page, "limit": limit, "items": users})
            return

        if self.command == "POST" and path == "/api/v1/users":
            token = self.get_bearer_token()
            if not self.state.require_token(token):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid or missing token"})
                return
            try:
                data = self.read_json()
                user = self.state.create_user(data)
            except ValueError as exc:
                self.send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(exc)})
                return
            self.send_json(HTTPStatus.CREATED, user)
            return

        if self.command == "GET" and path.startswith("/api/v1/users/"):
            token = self.get_bearer_token()
            if not self.state.require_token(token):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid or missing token"})
                return
            user_id = int(path.rsplit("/", 1)[-1])
            user = self.state.get_user(user_id)
            if user is None:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            self.send_json(HTTPStatus.OK, user)
            return

        if self.command == "PUT" and path.startswith("/api/v1/users/"):
            token = self.get_bearer_token()
            if not self.state.require_token(token):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid or missing token"})
                return
            user_id = int(path.rsplit("/", 1)[-1])
            try:
                data = self.read_json()
                user = self.state.update_user(user_id, data)
            except ValueError as exc:
                self.send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(exc)})
                return
            if user is None:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            self.send_json(HTTPStatus.OK, user)
            return

        if self.command == "DELETE" and path.startswith("/api/v1/users/"):
            token = self.get_bearer_token()
            if not self.state.require_token(token):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid or missing token"})
                return
            user_id = int(path.rsplit("/", 1)[-1])
            deleted = self.state.delete_user(user_id)
            if not deleted:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            self.send_json(HTTPStatus.OK, {"deleted": True, "id": user_id})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "endpoint not found"})

    def do_GET(self):
        self.handle_route()

    def do_POST(self):
        self.handle_route()

    def do_PUT(self):
        self.handle_route()

    def do_DELETE(self):
        self.handle_route()


class ApiEmulatorServer(ThreadingHTTPServer):
    def __init__(self, server_address, state_file=STATE_FILE):
        self.state = ApiEmulatorState(state_file)
        super().__init__(server_address, ApiEmulatorHandler)


def run_api_emulator(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, state_file: str | Path = STATE_FILE):
    server = ApiEmulatorServer((host, port), state_file=state_file)
    print(f"[api-emulator] listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[api-emulator] shutting down")
    finally:
        server.server_close()


def scan_api_contract(
    base_url: str = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}",
    username: str | None = None,
    password: str | None = None,
    token: str | None = None,
    login_route: str = "/auth/login",
    user_route: str = "/api/v1/users",
) -> dict:
    import urllib.request

    findings = []
    base = base_url.rstrip("/")

    def request_json(method: str, path: str, body=None, token_value=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(f"{base}{path}", data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token_value:
            req.add_header("Authorization", f"Bearer {token_value}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return resp.status, payload
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except Exception:
                payload = {"error": exc.reason}
            return exc.code, payload
        except Exception as exc:  # pragma: no cover - defensive fallback
            return 0, {"error": str(exc)}

    health_status, health_payload = request_json("GET", "/health")
    if health_status == 200:
        findings.append({"route": "/health", "status": health_status, "result": "ok"})
    else:
        findings.append({"route": "/health", "status": health_status, "result": health_payload})

    effective_token = token
    if not effective_token and username and password:
        login_status, login_payload = request_json("POST", login_route, {"username": username, "password": password})
        effective_token = login_payload.get("token") if login_status == 200 else None
        if effective_token:
            findings.append({"route": login_route, "status": login_status, "result": "token issued"})
        else:
            findings.append({"route": login_route, "status": login_status, "result": login_payload})
    elif not effective_token:
        findings.append({"route": "auth", "status": 0, "result": "no auth token or login credentials supplied"})

    metrics_status, metrics_payload = request_json("GET", "/api/v1/metrics", token_value=effective_token)
    if metrics_status == 200:
        findings.append({"route": "/api/v1/metrics", "status": metrics_status, "result": metrics_payload})
    else:
        findings.append({"route": "/api/v1/metrics", "status": metrics_status, "result": metrics_payload})

    users_status, users_payload = request_json("GET", f"{user_route}?page=1&limit=5", token_value=effective_token)
    if users_status == 200:
        findings.append({"route": user_route, "status": users_status, "result": f"{len(users_payload.get('items', []))} users returned"})
    else:
        findings.append({"route": user_route, "status": users_status, "result": users_payload})

    create_status, create_payload = request_json(
        "POST",
        user_route,
        {"name": "Charlie", "email": "charlie@example.com"},
        token_value=effective_token,
    )
    created_id = create_payload.get("id") if create_status == 201 else None
    if created_id:
        findings.append({"route": f"{user_route} POST", "status": create_status, "result": f"user {created_id} created"})
    else:
        findings.append({"route": f"{user_route} POST", "status": create_status, "result": create_payload})

    if created_id:
        read_status, read_payload = request_json("GET", f"{user_route}/{created_id}", token_value=effective_token)
        if read_status == 200:
            findings.append({"route": f"{user_route}/{created_id}", "status": read_status, "result": "user readable"})
        else:
            findings.append({"route": f"{user_route}/{created_id}", "status": read_status, "result": read_payload})

    return {
        "base_url": base_url,
        "contract_ok": all(item["status"] in (200, 201, 204) for item in findings if "status" in item and item["status"] != 0),
        "findings": findings,
        "token_issued": bool(effective_token),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Real local API emulator for authorized testing")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")
    parser.add_argument("--scan", action="store_true", help="Scan the emulator contract instead of starting the server")
    parser.add_argument("--state-file", default=str(STATE_FILE), help="Path to persisted emulator state")
    args = parser.parse_args()

    if args.scan:
        result = scan_api_contract(f"http://{args.host}:{args.port}")
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result.get("contract_ok") else 1)

    run_api_emulator(host=args.host, port=args.port, state_file=args.state_file)
