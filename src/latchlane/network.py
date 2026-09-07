"""Outbound HTTPS with public-IP pinning, no proxies, and no redirects."""
import base64
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit, quote

class NetworkError(Exception):
    pass


def validate_origin(origin):
    p = urlsplit(origin)
    if (p.scheme != "https" or not p.hostname or p.username or p.password or
        p.path not in ("", "/") or p.query or p.fragment or p.port not in (None, 443)):
        raise ValueError("Use an HTTPS origin such as https://api.example.com (port 443).")
    host = p.hostname.encode("idna").decode("ascii").lower()
    if ":" in host or any(c.isspace() for c in host): raise ValueError("Invalid hostname.")
    return "https://" + host


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, timeout=20, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, 443), self.timeout)
        try: self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def perform(key, operation):
    host = urlsplit(key["origin"]).hostname
    addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise NetworkError("Destination must resolve only to public IP addresses.")
    connection = PinnedHTTPS(host, sorted(addresses)[0])
    body = operation.get("body", "").encode()
    headers = {key["header"]: key["prefix"] + key["value"], "Accept": "application/json", "Content-Type": "application/json", "User-Agent": "Latchlane/0.1"}
    try:
        connection.request(operation["method"], operation["path"], body=body or None, headers=headers)
        response = connection.getresponse()
        if 300 <= response.status < 400: raise NetworkError("Redirect blocked; credentials were not forwarded.")
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024: raise NetworkError("Response exceeds 1 MiB.")
        text = data.decode("utf-8", errors="replace")
        # Best-effort accidental echo removal, not a defense against a malicious provider.
        value = key["value"]
        for form in (value, quote(value, safe=""), base64.b64encode(value.encode()).decode()):
            text = text.replace(form, "[credential redacted]")
        return {"status": response.status, "body": text}
    except NetworkError: raise
    except Exception: raise NetworkError("Provider connection failed; automatic retry disabled.") from None
    finally: connection.close()
