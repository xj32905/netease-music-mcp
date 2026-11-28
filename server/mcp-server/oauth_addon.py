"""Minimal OAuth 2.1 add-on for the NetEase Music MCP server (stdlib only).

Single-user, self-hosted model:
- The existing MCP_AUTH_TOKEN doubles as the password on the consent page.
- Clients run a standard authorization-code + PKCE flow and receive an access token.
- Legacy `Authorization: Bearer <MCP_AUTH_TOKEN>` keeps working unchanged.

Endpoints added (in-memory state; restart = clients re-authorize):
  GET  /.well-known/oauth-authorization-server
  GET  /.well-known/oauth-protected-resource
  GET  /authorize          consent form
  POST /authorize          password check -> 302 redirect with code
  POST /register           dynamic client registration (public clients)
  POST /token              authorization_code / refresh_token grants
"""
import base64, hashlib, html, json, os, secrets, time, urllib.parse

AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "").strip()

CODE_TTL = 600                 # authorization code: 10 minutes
ACCESS_TTL = 30 * 86400        # access token: 30 days
REFRESH_TTL = 90 * 86400       # refresh token: 90 days

_clients = {}          # client_id -> registration dict
_codes = {}            # code -> dict(client_id, redirect_uri, code_challenge, expires)
_access = {}           # token -> dict(client_id, expires)
_refresh = {}          # token -> dict(client_id, expires)


# ---------------------------------------------------------------- token store

def is_access_token(value):
    """Called by server.py's token_ok() for Bearer validation on /mcp."""
    if not value:
        return False
    entry = _access.get(value)
    if not entry:
        return False
    if entry["expires"] < time.time():
        _access.pop(value, None)
        return False
    return True


# ---------------------------------------------------------------- helpers

def _base(handler):
    """Public origin of this server, e.g. https://xxx.up.railway.app."""
    host = handler.headers.get("Host") or "localhost"
    proto = handler.headers.get("X-Forwarded-Proto")
    if not proto:
        proto = "https" if not host.startswith(("localhost", "127.0.0.1")) else "http"
    return "%s://%s" % (proto, host)


def _json(handler, status, obj):
    handler._send(status, obj)


def _html(handler, status, text):
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _redirect(handler, location):
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _form(handler):
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        length = 0
    if length <= 0 or length > 65536:
        return {}
    raw = handler.rfile.read(length).decode("utf-8", "replace")
    return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}


def _pkce_ok(verifier, challenge):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == challenge


def _new_token():
    return secrets.token_urlsafe(32)


def _prune():
    now = time.time()
    for store in (_codes, _access, _refresh):
        for key in [k for k, v in store.items() if v["expires"] < now]:
            store.pop(key, None)


# ---------------------------------------------------------------- consent page

_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权 - NetEase Music MCP</title>
<style>
body{{background:#141419;color:#e8e8ee;font-family:system-ui,sans-serif;
display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}
.card{{background:#1e1e28;border-radius:16px;padding:32px;max-width:380px;width:90%}}
h1{{font-size:20px;margin:0 0 8px}}p{{color:#9a9aad;font-size:14px;line-height:1.6}}
input[type=password]{{width:100%;box-sizing:border-box;padding:12px;margin:16px 0;
border-radius:8px;border:1px solid #3a3a4a;background:#141419;color:#e8e8ee;font-size:16px}}
button{{width:100%;padding:12px;border:0;border-radius:8px;background:#1783ff;
color:#fff;font-size:16px;cursor:pointer}}
.err{{color:#ff7d60;font-size:14px}}
</style></head><body><div class="card">
<h1>授权访问网易云 MCP</h1>
<p>应用 <b>{client}</b> 请求使用你的 NetEase Music MCP 服务（24 个工具）。
授权后它可以查询播放记录、搜索音乐、管理你的歌单。</p>
{error}
<form method="post" action="/authorize">{hidden}
<input type="password" name="password" placeholder="输入 MCP_AUTH_TOKEN" required autofocus>
<button type="submit">同意授权</button></form>
<p>密码即你部署时设置的 MCP_AUTH_TOKEN，仅你自己持有。</p>
</div></body></html>"""


def _render_form(handler, params, error="", status=200):
    # Preserve every OAuth authorization parameter across the consent form POST.
    # In particular, dropping response_type makes the POST fail its own validation.
    fields = ("response_type", "client_id", "redirect_uri", "state", "code_challenge",
              "code_challenge_method", "resource")
    hidden = "".join(
        '<input type="hidden" name="%s" value="%s">' % (f, html.escape(params.get(f, ""), quote=True))
        for f in fields)
    client = html.escape(_clients.get(params.get("client_id", ""), {}).get("client_name") or "未知应用")
    err = '<p class="err">%s</p>' % html.escape(error) if error else ""
    _html(handler, status, _PAGE.format(client=client, hidden=hidden, error=err))


def _auth_params(handler):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query)
    return {k: v[0] for k, v in q.items()}


def _validate_auth_params(handler, p):
    """Returns an error string, or None when the /authorize request is well-formed."""
    if p.get("response_type") != "code":
        return "response_type 必须是 code"
    client = _clients.get(p.get("client_id", ""))
    if not client:
        return "未知 client_id，请先完成客户端注册"
    if p.get("redirect_uri") not in client["redirect_uris"]:
        return "redirect_uri 与注册时不一致"
    if not p.get("code_challenge") or p.get("code_challenge_method", "S256") != "S256":
        return "需要 PKCE（code_challenge_method=S256）"
    return None


# ---------------------------------------------------------------- route handlers

def handle_get(handler, path):
    if path == "/.well-known/oauth-authorization-server":
        base = _base(handler)
        _json(handler, 200, {
            "issuer": base,
            "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token",
            "registration_endpoint": base + "/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["mcp"],
        })
        return True

    if path == "/.well-known/oauth-protected-resource":
        base = _base(handler)
        _json(handler, 200, {
            "resource": base,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        })
        return True

    if path == "/authorize":
        p = _auth_params(handler)
        err = _validate_auth_params(handler, p)
        if err:
            _html(handler, 400, "<meta charset='utf-8'>授权请求无效：" + html.escape(err))
        else:
            _render_form(handler, p)
        return True

    return False


def handle_post(handler, path):
    if path == "/register":
        try:
            length = int(handler.headers.get("Content-Length") or 0)
            data = json.loads(handler.rfile.read(length) or b"{}")
        except (ValueError, TypeError):
            return _json(handler, 400, {"error": "invalid_client_metadata"}), True
        uris = data.get("redirect_uris") or []
        if not isinstance(uris, list) or not uris:
            return _json(handler, 400, {"error": "invalid_redirect_uri"}), True
        client_id = _new_token()
        _clients[client_id] = {
            "redirect_uris": uris,
            "client_name": data.get("client_name", ""),
        }
        _json(handler, 201, {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "client_name": data.get("client_name", ""),
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })
        return True

    if path == "/authorize":
        p = _form(handler)
        err = _validate_auth_params(handler, p)
        if err:
            _html(handler, 400, "<meta charset='utf-8'>授权请求无效：" + html.escape(err))
            return True
        if not AUTH_TOKEN or not secrets.compare_digest(p.get("password", ""), AUTH_TOKEN):
            _render_form(handler, p, error="密码不对，再试一次", status=401)
            return True
        code = _new_token()
        _codes[code] = {
            "client_id": p["client_id"],
            "redirect_uri": p["redirect_uri"],
            "code_challenge": p["code_challenge"],
            "expires": time.time() + CODE_TTL,
        }
        q = {"code": code}
        if p.get("state"):
            q["state"] = p["state"]
        sep = "&" if "?" in p["redirect_uri"] else "?"
        _redirect(handler, p["redirect_uri"] + sep + urllib.parse.urlencode(q))
        return True

    if path == "/token":
        return _token(handler), True

    return False


def _token(handler):
    _prune()
    p = _form(handler)
    grant = p.get("grant_type")

    if grant == "authorization_code":
        code = _codes.pop(p.get("code", ""), None)
        if not code or code["expires"] < time.time():
            return _json(handler, 400, {"error": "invalid_grant"})
        if p.get("client_id") != code["client_id"] or p.get("redirect_uri") != code["redirect_uri"]:
            return _json(handler, 400, {"error": "invalid_grant"})
        if not _pkce_ok(p.get("code_verifier", ""), code["code_challenge"]):
            return _json(handler, 400, {"error": "invalid_grant"})
        client_id = code["client_id"]
    elif grant == "refresh_token":
        old = _refresh.get(p.get("refresh_token", ""))
        if not old or old["expires"] < time.time():
            return _json(handler, 400, {"error": "invalid_grant"})
        client_id = old["client_id"]
    else:
        return _json(handler, 400, {"error": "unsupported_grant_type"})

    access, refresh = _new_token(), _new_token()
    now = time.time()
    _access[access] = {"client_id": client_id, "expires": now + ACCESS_TTL}
    _refresh[refresh] = {"client_id": client_id, "expires": now + REFRESH_TTL}
    _json(handler, 200, {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh,
        "scope": "mcp",
    })
