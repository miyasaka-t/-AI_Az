# import os, time, json, base64, secrets, requests, html as _html
# from flask import Flask, request, jsonify, redirect, render_template, Response
# from flask_cors import CORS
# from email.message import EmailMessage
# from email.utils import formatdate
# from datetime import datetime
# from urllib.parse import quote

# app = Flask(__name__, template_folder="templates")
# CORS(app, resources={r"/api/*": {"origins": "*"}, r"/tickets/*": {"origins": "*"}})

# # ===== Azure OAuth / Graph (OneDrive 個人用/MSA向け) =====
# CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
# CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
# TENANT = os.getenv("AZURE_TENANT", "consumers")  # 個人用なら "consumers"
# REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "https://ai-az.onrender.com/callback")
# SCOPE = "offline_access Files.ReadWrite"

# GRAPH = "https://graph.microsoft.com/v1.0"
# AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
# TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# # ===== 簡易メモリ・トークン保管（REFRESH_TOKEN は環境変数で永続） =====
# TOKENS = {"access_token": None, "refresh_token": os.getenv("REFRESH_TOKEN"), "exp": 0}

# def save_tokens(j: dict):
#     TOKENS["access_token"] = j["access_token"]
#     if j.get("refresh_token"):
#         TOKENS["refresh_token"] = j["refresh_token"]
#     TOKENS["exp"] = time.time() + int(j.get("expires_in", 3600)) - 60

# def need_refresh() -> bool:
#     return not TOKENS["access_token"] or time.time() >= TOKENS["exp"]

# def refresh_if_needed():
#     if not need_refresh():
#         return
#     if not TOKENS["refresh_token"]:
#         raise RuntimeError("Not authenticated. Set REFRESH_TOKEN or open /login.")
#     data = {
#         "client_id": CLIENT_ID,
#         "client_secret": CLIENT_SECRET,
#         "grant_type": "refresh_token",
#         "refresh_token": TOKENS["refresh_token"],
#         "redirect_uri": REDIRECT_URI,
#     }
#     r = requests.post(TOKEN, data=data, timeout=30)
#     r.raise_for_status()
#     save_tokens(r.json())

# # ===== OAuthフロー（個人用） =====
# @app.get("/login")
# def login():
#     url = (
#         f"{AUTHZ}?client_id={CLIENT_ID}"
#         f"&response_type=code"
#         f"&redirect_uri={quote(REDIRECT_URI, safe='')}"
#         f"&scope={quote(SCOPE, safe=' ')}"
#         f"&prompt=select_account"
#         f"&domain_hint=consumers"
#     )
#     return redirect(url)

# @app.get("/callback")
# def callback():
#     code = request.args.get("code")
#     if not code:
#         return "missing code", 400
#     data = {
#         "client_id": CLIENT_ID,
#         "client_secret": CLIENT_SECRET,
#         "grant_type": "authorization_code",
#         "code": code,
#         "redirect_uri": REDIRECT_URI,
#     }
#     r = requests.post(TOKEN, data=data, timeout=30)
#     if not r.ok:
#         return f"OAuth error: {r.status_code} {r.text}", 400
#     token_info = r.json()
#     save_tokens(token_info)

#     rt = token_info.get("refresh_token", "")
#     html = f"""
#     <h3>OAuth OK</h3>
#     <p>Render の Environment に <code>REFRESH_TOKEN</code> として保存してね。</p>
#     <pre style="white-space: pre-wrap;">{rt}</pre>
#     <p>保存後にサービス再起動すると、以後は自動更新（90日未使用で失効のことあり）。</p>
#     """
#     return html, 200

# @app.get("/logout")
# def logout():
#     TOKENS.update({"access_token": None, "refresh_token": None, "exp": 0})
#     return jsonify({"ok": True})

# @app.get("/")
# def health():
#     return "OK"

# # ===== フロント配信用（同一オリジンで使う場合） =====
# @app.get("/front")
# def front():
#     # 例: https://ai-az.onrender.com/front?ticket=...&suggest=Report.txt
#     return render_template("onedrive.html")

# @app.get("/picker-redirect.html")
# def picker_redirect():
#     html = "<!doctype html><meta charset='utf-8'><title>Picker Redirect</title><p>Closing…</p>"
#     return Response(html, mimetype="text/html")

# # ===== テキスト -> HTML 自動変換（段落/改行保持） =====
# def _text_to_html(s: str) -> str:
#     if not s:
#         return "<p></p>"
#     t = (_html.escape(s or "")
#          .replace("\r\n", "\n")
#          .replace("\r", "\n"))
#     paras = t.split("\n\n")
#     html_body = "".join(f"<p>{p.replace('\n','<br>')}</p>" for p in paras)
#     return html_body or "<p></p>"

# # ===== EML生成 =====
# def build_eml_bytes(subject, from_addr, to_addrs, body_text="", body_html=None, date_str=None) -> bytes:
#     msg = EmailMessage()
#     msg["Subject"] = subject or "LLM Output"
#     msg["From"] = from_addr or "noreply@example.com"
#     msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else (to_addrs or "")
#     msg["Date"] = date_str or formatdate(localtime=True)

#     msg.set_content(body_text or "", subtype="plain", charset="utf-8")

#     if body_html is None or body_html is False:
#         body_html = _text_to_html(body_text or "")

#     if body_html:
#         msg.add_alternative(body_html, subtype="html", charset="utf-8")

#     return msg.as_bytes()

# # ===== チケット管理（メモリ／短命） =====
# TICKETS = {}  # tid -> dict
# def _now(): return int(time.time())

# def issue_ticket(file_name: str, mime: str, payload: dict, ttl_sec: int = 600, once: bool = True):
#     tid = secrets.token_urlsafe(24)
#     TICKETS[tid] = {
#         "file_name": file_name,
#         "mime": mime or "application/octet-stream",
#         "payload": payload,    # {"type":"text"|"base64"|"url"|"eml", ...}
#         "expire_at": _now() + int(ttl_sec or 600),
#         "used": False,
#         "once": bool(once),
#     }
#     return tid, ttl_sec

# def redeem_ticket(tid: str, consume: bool = False):
#     meta = TICKETS.get(tid)
#     if not meta:
#         raise RuntimeError("ticket not found or expired")
#     if _now() > meta["expire_at"]:
#         TICKETS.pop(tid, None)
#         raise RuntimeError("ticket expired")
#     if meta["once"] and meta["used"] and consume:
#         raise RuntimeError("ticket already used")
#     if consume and meta["once"]:
#         meta["used"] = True
#     return meta

# # ===== チケット作成 =====
# @app.post("/tickets/create")
# def tickets_create():
#     """
#     Dify から叩く:
#     {
#       "fileName": "Report_2025-08-26.txt",
#       "mime": "text/plain",
#       "payload": { "type":"text", "body":"<<LLM出力>>" },  # text/base64/url/eml に対応
#       "ttlSec": 600,
#       "once": true
#     }
#     """
#     try:
#         j = request.get_json(force=True) or {}
#         payload = j.get("payload") or {"type": "text", "body": ""}
#         ptype = (payload.get("type") or "text").lower()

#         ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
#         default_name = f"llm_{ts}.eml" if ptype == "eml" else f"llm_{ts}.txt"
#         fn = j.get("fileName") or default_name

#         if ptype == "eml" and not fn.lower().endswith(".eml"):
#             fn = fn + ".eml"

#         mime = j.get("mime")
#         if not mime:
#             mime = "message/rfc822" if ptype == "eml" else "application/octet-stream"

#         ttl = int(j.get("ttlSec", 600))
#         once = bool(j.get("once", True))
#         tid, ttl_sec = issue_ticket(fn, mime, payload, ttl, once)
#         return jsonify({"ticket": tid, "expiresIn": ttl_sec})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

# # ===== チケット内容の確認用（消費しない Peek） =====
# @app.get("/tickets/peek")
# def tickets_peek():
#     """
#     クエリ: ?ticket=<ticket id>
#     戻り値: {"fileName": "...", "mime":"...", "type":"eml|text|base64|url"}
#     """
#     try:
#         tid = request.args.get("ticket", "")
#         if not tid:
#             return jsonify({"error": "missing ticket"}), 400
#         meta = redeem_ticket(tid, consume=False)
#         p = meta.get("payload") or {}
#         return jsonify({
#             "fileName": meta.get("file_name"),
#             "mime": meta.get("mime"),
#             "type": (p.get("type") or "text").lower()
#         })
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

# # ===== payload を bytes に実体化 =====
# def materialize_bytes(meta: dict) -> bytes:
#     p = meta["payload"] or {}
#     t = (p.get("type") or "text").lower()
#     if t == "text":
#         return (p.get("body") or "").encode("utf-8")
#     if t == "base64":
#         return base64.b64decode(p.get("data") or "")
#     if t == "url":
#         u = p.get("href")
#         if not u:
#             raise RuntimeError("payload.url missing")
#         r = requests.get(u, timeout=60)
#         r.raise_for_status()
#         return r.content
#     if t == "eml":
#         body_text = p.get("text", "") or ""
#         html_from_text = bool(p.get("htmlFromText"))
#         body_html = p.get("html")
#         if html_from_text or body_html in (None, False, ""):
#             body_html = _text_to_html(body_text)
#         return build_eml_bytes(
#             subject=p.get("subject"),
#             from_addr=p.get("from"),
#             to_addrs=p.get("to") or ["user@example.com"],
#             body_text=body_text,
#             body_html=body_html,
#             date_str=p.get("date")
#         )
#     raise RuntimeError(f"unsupported payload.type: {t}")

# # ===== OneDrive(個人) へアップロード =====
# def graph_put_small_to_folder(folder_id: str, name: str, mime: str, data: bytes):
#     refresh_if_needed()
#     url = f"{GRAPH}/me/drive/items/{folder_id}:/{quote(name, safe='')}:/content"
#     r = requests.put(url, headers={
#         "Authorization": f"Bearer {TOKENS['access_token']}",
#         "Content-Type": mime or "application/octet-stream"
#     }, data=data, timeout=120)
#     return r

# def graph_put_chunked_to_folder(folder_id: str, name: str, data: bytes):
#     refresh_if_needed()
#     sess_url = f"{GRAPH}/me/drive/items/{folder_id}:/{quote(name, safe='')}:/createUploadSession"
#     sess = requests.post(
#         sess_url,
#         headers={"Authorization": f"Bearer {TOKENS['access_token']}", "Content-Type": "application/json"},
#         json={"item": {"@microsoft.graph.conflictBehavior": "replace", "name": name}},
#         timeout=30
#     )
#     if not sess.ok:
#         return sess
#     upload_url = sess.json()["uploadUrl"]
#     CHUNK = 10 * 1024 * 1024
#     size = len(data)
#     pos = 0
#     last = None
#     while pos < size:
#         chunk = data[pos:pos + CHUNK]
#         headers = {
#             "Content-Length": str(len(chunk)),
#             "Content-Range": f"bytes {pos}-{pos + len(chunk) - 1}/{size}"
#         }
#         last = requests.put(upload_url, headers=headers, data=chunk, timeout=120)
#         if last.status_code not in (200, 201, 202):
#             break
#         pos += len(chunk)
#     return last

# # ===== OneDriveアイテム詳細（name/webUrl を取得） =====
# @app.get("/api/drive/item")
# def api_drive_item():
#     """
#     ?id=<item_id> を受け、OneDriveの name / webUrl を返す
#     """
#     try:
#         item_id = request.args.get("id")
#         if not item_id:
#             return jsonify({"error": "missing id"}), 400
#         refresh_if_needed()
#         url = f"{GRAPH}/me/drive/items/{quote(item_id, safe='')}"
#         r = requests.get(url, headers={"Authorization": f"Bearer {TOKENS["access_token"]}"}, timeout=20)
#         if not r.ok:
#             return jsonify({"error": "graph", "status": r.status_code, "detail": r.text}), r.status_code
#         j = r.json()
#         return jsonify({"name": j.get("name"), "webUrl": j.get("webUrl")})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

# # ===== アップロードAPI =====
# @app.post("/api/upload")
# def api_upload():
#     """
#     front(onedrive.html) から:
#       ticket, folderId, (optional) fileName
#     """
#     try:
#         ticket    = request.form.get("ticket")
#         folder_id = request.form.get("folderId")
#         name_ovr  = request.form.get("fileName")
#         if not all([ticket, folder_id]):
#             return jsonify({"error": "missing parameters"}), 400

#         meta = redeem_ticket(ticket, consume=True)  # 使い捨て
#         data = materialize_bytes(meta)
#         name = name_ovr or meta["file_name"]
#         mime = meta.get("mime", "application/octet-stream")

#         # ~250MB以下は一発、超過は分割
#         if len(data) <= 250 * 1024 * 1024:
#             r = graph_put_small_to_folder(folder_id, name, mime, data)
#         else:
#             r = graph_put_chunked_to_folder(folder_id, name, data)

#         if r.status_code in (200, 201):
#             item = r.json()
#             return jsonify({"ok": True, "id": item.get("id"), "webUrl": item.get("webUrl"), "name": item.get("name")})
#         else:
#             return jsonify({"error": "graph upload failed", "status": r.status_code, "detail": r.text}), r.status_code
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))


# ============================================

# app.py
import os, io, re, json, time, base64, mimetypes, tempfile
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import requests
from urllib.parse import quote

# （必要なら CORS を有効化）
# from flask_cors import CORS

# ===============================
# 設定（環境変数）
# ===============================
TENANT_ID      = os.getenv("AZ_TENANT_ID", "")
CLIENT_ID      = os.getenv("AZ_CLIENT_ID", "")
CLIENT_SECRET  = os.getenv("AZ_CLIENT_SECRET", "")
TARGET_USER_ID = os.getenv("TARGET_USER_ID", "")  # アプリ権限時は /users/{id} 必須

GRAPH_BASE   = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE  = "https://graph.microsoft.com/.default"

# アップロード閾値
SMALL_MAX_BYTES = 250 * 1024 * 1024  # 250MB
CHUNK_SIZE      = 5 * 1024 * 1024    # 5MB

# チケットの有効期限（秒）
DEFAULT_TICKET_TTL = 600

# ===============================
# Flask
# ===============================
app = Flask(__name__, static_folder="static", template_folder="templates")
# CORS(app)

# ===============================
# 簡易チケットストア（メモリ）
# ===============================
@dataclass
class Ticket:
    created_at: float
    expires_at: float
    meta: Dict[str, Any]   # {type, fileName, mime?, data?, href? ...}

_TICKETS: Dict[str, Ticket] = {}

def _now() -> float:
    return time.time()

def _gen_ticket_id(n: int = 24) -> str:
    # 簡易ID（URLセーフ）
    return base64.urlsafe_b64encode(os.urandom(n)).decode("ascii").rstrip("=")

def _cleanup_tickets():
    now = _now()
    expired = [k for k, v in _TICKETS.items() if v.expires_at < now]
    for k in expired:
        _TICKETS.pop(k, None)

def save_ticket(meta: Dict[str, Any], ttl: int = DEFAULT_TICKET_TTL) -> str:
    _cleanup_tickets()
    tid = _gen_ticket_id()
    _TICKETS[tid] = Ticket(created_at=_now(), expires_at=_now() + max(10, ttl), meta=meta)
    return tid

def get_ticket(tid: str) -> Optional[Ticket]:
    _cleanup_tickets()
    return _TICKETS.get(tid)

def redeem_ticket(tid: str, consume: bool = True) -> Dict[str, Any]:
    """
    チケットを取得（必要なら消費）。見つからなければ KeyError。
    """
    t = get_ticket(tid)
    if not t:
        raise KeyError("ticket_not_found_or_expired")
    meta = t.meta
    if consume:
        _TICKETS.pop(tid, None)
    return meta

# ===============================
# Graph 認証＆ヘッダ（組織用）
# ===============================
def get_app_token() -> str:
    if not (TENANT_ID and CLIENT_ID and CLIENT_SECRET):
        raise RuntimeError("Graph app-only requires AZ_TENANT_ID/CLIENT_ID/CLIENT_SECRET")
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": GRAPH_SCOPE,
        "grant_type": "client_credentials",
    }
    r = requests.post(url, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def gheaders(token: str, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {"Authorization": f"Bearer {token}"}
    if extra:
        h.update(extra)
    return h

# ===============================
# OneDrive（組織: /users/{id}/drive）
# ===============================
def _user_drive_root() -> str:
    if not TARGET_USER_ID:
        raise RuntimeError("TARGET_USER_ID is required for app-only Graph calls")
    return f"{GRAPH_BASE}/users/{TARGET_USER_ID}/drive"

def graph_get_item_meta(item_id: str) -> Dict[str, Any]:
    token = get_app_token()
    url = f"{_user_drive_root()}/items/{item_id}"
    r = requests.get(url, headers=gheaders(token), timeout=30)
    r.raise_for_status()
    return r.json()

def _sanitize_name(name: str) -> str:
    safe = (name or "upload.bin").replace("/", "_").replace("\\", "_").strip()
    return safe or "upload.bin"

def graph_put_small_to_folder(folder_id: str, name: str, mime: str, data: bytes) -> requests.Response:
    """
    親フォルダID配下に name をアップロード（<= SMALL_MAX_BYTES）
    PUT /users/{id}/drive/items/{parent-id}:/{name}:/content
    """
    token = get_app_token()
    safe_name = _sanitize_name(name)
    url = f"{_user_drive_root()}/items/{folder_id}:/{safe_name}:/content"
    return requests.put(url, headers=gheaders(token, {"Content-Type": mime or "application/octet-stream"}),
                        data=data, timeout=300)

def graph_create_upload_session(folder_id: str, name: str) -> str:
    """
    大きいファイル用Upload Session
    POST /users/{id}/drive/items/{parent-id}:/{name}:/createUploadSession
    """
    token = get_app_token()
    safe_name = _sanitize_name(name)
    url = f"{_user_drive_root()}/items/{folder_id}:/{safe_name}:/createUploadSession"
    r = requests.post(url, headers=gheaders(token, {"Content-Type": "application/json"}), json={}, timeout=60)
    r.raise_for_status()
    up = r.json()
    return up["uploadUrl"]

def graph_put_chunked_to_folder(folder_id: str, name: str, data: bytes) -> requests.Response:
    upload_url = graph_create_upload_session(folder_id, name)
    size = len(data)
    off = 0
    while off < size:
        chunk = data[off: off + CHUNK_SIZE]
        start = off
        end = off + len(chunk) - 1
        headers = {
            "Content-Length": str(len(chunk)),
            "Content-Range": f"bytes {start}-{end}/{size}",
            "Content-Type": "application/octet-stream",
        }
        r = requests.put(upload_url, headers=headers, data=chunk, timeout=600)
        if r.status_code not in (200, 201, 202):
            r.raise_for_status()
        off += len(chunk)
    return r

# ===============================
# チケット -> 実バイト列生成
# ===============================
def _to_str(v: Any) -> str:
    if v is None:
        return ""
    s = str(v)
    return s.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ").strip()

def _build_eml(metadata: Dict[str, Any]) -> Tuple[str, bytes, str]:
    """
    payload 例:
      {
        "type": "eml",
        "subject": "...",
        "from": "noreply@example.com",
        "to": ["a@b"],
        "text": "本文",
        "htmlFromText": true,
        "date": "Wed, 27 Aug 2025 09:30:00 +0900"
      }
    """
    payload = metadata.get("payload", {}) or {}
    file_name = metadata.get("fileName") or "message"
    if not file_name.lower().endswith(".eml"):
        file_name += ".eml"

    subj = _to_str(payload.get("subject") or "")
    frm  = _to_str(payload.get("from") or "noreply@example.com")
    tos  = payload.get("to") or []
    if isinstance(tos, str):
        tos = [tos]
    date = _to_str(payload.get("date") or "")
    text = payload.get("text") or ""
    html_from_text = bool(payload.get("htmlFromText"))

    if html_from_text:
        body = f'<html><body><pre style="white-space:pre-wrap">{text}</pre></body></html>'
        content_type = 'text/html; charset="utf-8"'
    else:
        body = text
        content_type = 'text/plain; charset="utf-8"'

    headers = []
    headers.append(f"From: {frm}")
    if tos:
        headers.append("To: " + ", ".join(tos))
    if subj:
        headers.append(f"Subject: {subj}")
    if date:
        headers.append(f"Date: {date}")
    headers.append("MIME-Version: 1.0")
    headers.append(f"Content-Type: {content_type}")
    headers.append("Content-Transfer-Encoding: 8bit")

    raw = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body.encode("utf-8")
    return file_name, raw, "message/rfc822"

def materialize_bytes(meta: Dict[str, Any]) -> Tuple[str, bytes, str]:
    """
    meta["type"] ∈ {"text","base64","url","eml"}
    """
    mtype = (meta.get("type") or "text").lower()
    file_name = meta.get("fileName") or "download.bin"
    mime = meta.get("mime") or mimetypes.guess_type(file_name)[0] or "application/octet-stream"

    if mtype == "text":
        data_str = meta.get("data") or ""
        return file_name, data_str.encode("utf-8"), mime

    if mtype == "base64":
        b64 = meta.get("data") or ""
        try:
            data = base64.b64decode(b64, validate=True)
        except Exception:
            data = base64.b64decode(b64)
        return file_name, data, mime

    if mtype == "url":
        href = meta.get("href") or ""
        if not href:
            raise ValueError("url type requires href")
        r = requests.get(href, timeout=60)
        r.raise_for_status()
        cm = r.headers.get("content-type")
        if cm:
            mime = cm.split(";")[0].strip()
        return file_name, r.content, mime

    if mtype == "eml":
        fname, raw, mime2 = _build_eml(meta)
        return fname, raw, mime2

    data_str = meta.get("data") or ""
    return file_name, data_str.encode("utf-8"), mime

# ===============================
# .msg から Excel 添付抽出
# ===============================
def _extract_first_excel_from_msg(msg_bytes: bytes):
    """
    .msgバイナリから最初の Excel(CSV含む) を抽出
    戻り値: (filename, data_bytes, mime) / None
    """
    import extract_msg  # pip install extract-msg
    with tempfile.NamedTemporaryFile(suffix=".msg", delete=True) as tmp:
        tmp.write(msg_bytes)
        tmp.flush()
        m = extract_msg.Message(tmp.name)
        for att in m.attachments:
            fname = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment"
            lower = fname.lower()
            if lower.endswith((".xlsx", ".xlsm", ".xls", ".csv")):
                data = att.data
                mime = (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if lower.endswith(".xlsx") else
                    "application/vnd.ms-excel" if lower.endswith((".xls", ".xlsm")) else
                    "text/csv" if lower.endswith(".csv") else
                    mimetypes.guess_type(fname)[0] or "application/octet-stream"
                )
                return fname, data, mime
    return None

# ===============================
# ルーティング：静的ページ
# ===============================
@app.get("/")
def index():
    # バージョンで新コード稼働確認
    return jsonify({"ok": True, "service": "onedrive-uploader", "version": "2025-08-29-batch-multi-fixed2"})

@app.get("/front")
def serve_front():
    return send_from_directory(app.template_folder, "onedrive.html")

@app.get("/picker-redirect.html")
def picker_redirect():
    return "<!doctype html><meta charset='utf-8'><title>close</title>OK"

# ===============================
# API：チケット作成 / 参照 / ダウンロード（個人用）
# ===============================
@app.post("/tickets/create")
def tickets_create():
    """
    JSON:
      {
        "type": "text|base64|url|eml",
        "fileName": "name.ext",
        "mime": "optional",
        "data": "...",       # text/base64
        "href": "https://",  # url
        "payload": {...},    # eml用
        "ttlSec": 600
      }
    """
    try:
        j = request.get_json(force=True, silent=False)
        if not j:
            return jsonify({"error": "empty_body"}), 400

        mtype = (j.get("type") or "text").lower()
        meta = {
            "type": mtype,
            "fileName": j.get("fileName") or "download.bin",
            "mime": j.get("mime"),
        }
        if mtype in ("text", "base64"):
            meta["data"] = j.get("data") or ""
        elif mtype == "url":
            meta["href"] = j.get("href") or ""
        elif mtype == "eml":
            meta["payload"] = j.get("payload") or {}
        else:
            meta["data"] = j.get("data") or ""

        ttl = int(j.get("ttlSec") or DEFAULT_TICKET_TTL)
        tid = save_ticket(meta, ttl=ttl)
        return jsonify({"ticket": tid})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/tickets/create-multipart")
def tickets_create_multipart():
    """
    form-data:
      file      : (任意) アップロードファイル。あれば base64 チケット（=原文）を作成
      metadata  : (任意) JSON文字列。type='eml' 等なら file 無しでも作成可
                   追加オプション:
                     extractXlsx: true  # file(.msg)がある時、最初のExcelを抽出→別ticketも返す
                     fileName, mime, ttlSec, xlsxFileName
    戻り: {"ok":true,"tickets":{"file":..., "metadata":..., "xlsxFromMsg":...}}
    """
    try:
        # 1) metadata を form テキスト → files → 別名 の順で救済的に読む
        meta_text = request.form.get("metadata", "") or ""
        if not meta_text and "metadata" in request.files:
            try:
                meta_text = request.files["metadata"].read().decode("utf-8", errors="ignore")
            except Exception:
                meta_text = ""
        if not meta_text:
            meta_text = request.form.get("meta", "") or request.form.get("metadata_json", "") or ""

        meta_json = {}
        if meta_text and meta_text.strip():
            try:
                meta_json = json.loads(meta_text)
            except Exception:
                print("[create-multipart] WARN: metadata JSON parse failed")
                meta_json = {}

        # 簡易ログ（Renderのログで確認用）
        print("[create-multipart] has_file=", bool(request.files.get("file")))
        print("[create-multipart] meta_json_keys=", list(meta_json.keys()) if meta_json else [])
        print("[create-multipart] extractXlsx=", meta_json.get("extractXlsx") if meta_json else None)

        ttl = int(meta_json.get("ttlSec") or DEFAULT_TICKET_TTL)

        made_file_ticket = None
        made_meta_ticket = None
        made_xlsx_ticket = None

        f = request.files.get("file")
        raw = None

        # 2) file → 原文ticket
        if f:
            raw = f.read()
            up_name = getattr(f, "filename", None) or "upload.bin"
            file_name_for_file = (meta_json.get("fileName") or up_name or "upload.bin").strip() or "upload.bin"
            file_mime_for_file = (
                meta_json.get("mime")
                or f.mimetype
                or mimetypes.guess_type(file_name_for_file)[0]
                or "application/octet-stream"
            )
            made_file_ticket = save_ticket({
                "type": "base64",
                "fileName": file_name_for_file,
                "mime": file_mime_for_file,
                "data": base64.b64encode(raw).decode("ascii"),
            }, ttl=ttl)

        # 3) metadata → eml/text/url 等の ticket
        if meta_json:
            mtype = (meta_json.get("type") or "text").lower()
            meta = {
                "type": mtype,
                "fileName": meta_json.get("fileName") or "download.bin",
                "mime": meta_json.get("mime"),
            }
            if mtype in ("text", "base64"):
                meta["data"] = meta_json.get("data") or ""
            elif mtype == "url":
                meta["href"] = meta_json.get("href") or ""
            elif mtype == "eml":
                meta["payload"] = meta_json.get("payload") or {}
            else:
                meta["data"] = meta_json.get("data") or ""
            made_meta_ticket = save_ticket(meta, ttl=ttl)

        # 4) .msg → Excel 抽出（オプション）
        if f and raw is not None and meta_json.get("extractXlsx"):
            hit = _extract_first_excel_from_msg(raw)
            if hit:
                att_name, att_bytes, att_mime = hit
                save_name = (meta_json.get("xlsxFileName") or att_name or "attachment.xlsx").strip()
                if not save_name.lower().endswith((".xlsx", ".xlsm", ".xls", ".csv")):
                    save_name += ".xlsx"
                made_xlsx_ticket = save_ticket({
                    "type": "base64",
                    "fileName": save_name,
                    "mime": att_mime or "application/octet-stream",
                    "data": base64.b64encode(att_bytes).decode("ascii")
                }, ttl=ttl)

        # 常にまとめ形式で返す
        return jsonify({
            "ok": True,
            "tickets": {
                "file": made_file_ticket,
                "metadata": made_meta_ticket,
                "xlsxFromMsg": made_xlsx_ticket
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.get("/tickets/peek")
def tickets_peek():
    tid = request.args.get("ticket", "")
    t = get_ticket(tid)
    if not t:
        return jsonify({"error": "ticket_not_found_or_expired"}), 404
    meta = t.meta
    fn = meta.get("fileName") or "download.bin"
    if (meta.get("type") or "").lower() == "eml" and not fn.lower().endswith(".eml"):
        fn = fn + ".eml"
    return jsonify({"fileName": fn, "type": meta.get("type") or "text", "expiresAt": t.expires_at})

@app.get("/tickets/download")
def tickets_download():
    """
    個人 OneDrive 用：チケット内容を実体ファイルで返す
    GET /tickets/download?ticket=...
    """
    tid = request.args.get("ticket", "")
    if not tid:
        return jsonify({"error": "missing ticket"}), 400
    try:
        meta = redeem_ticket(tid, consume=False)  # 個人saveで複数回使えるよう非消費
        file_name, data_bytes, mime = materialize_bytes(meta)
        if (meta.get("type") or "").lower() == "eml" and not file_name.lower().endswith(".eml"):
            file_name += ".eml"
        safe = _sanitize_name(file_name)
        disp = f"attachment; filename*=UTF-8''{quote(safe)}; filename=\"{safe}\""
        resp = app.response_class(response=data_bytes, status=200, mimetype=mime or "application/octet-stream")
        resp.headers["Content-Disposition"] = disp
        resp.headers["Content-Length"] = str(len(data_bytes))
        return resp
    except KeyError:
        return jsonify({"error": "ticket_not_found_or_expired"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===============================
# API：.msg → Excel を ticket 化（個人向け save 用）
# ===============================
@app.post("/api/msg-to-xlsx-ticket")
def api_msg_to_xlsx_ticket():
    """
    form-data/json:
      ticket: .msg を指す ticket
      fileName: 任意（上書き名）
    -> {"ticket": "<xlsx用の新ticket>"}
    """
    try:
        if request.is_json:
            t = (request.json or {}).get("ticket")
            name_ovr = (request.json or {}).get("fileName")
        else:
            t = request.values.get("ticket")
            name_ovr = request.values.get("fileName")

        if not t:
            return jsonify({"error": "missing ticket"}), 400

        meta = redeem_ticket(t, consume=False)
        _, msg_bytes, _ = materialize_bytes(meta)
        hit = _extract_first_excel_from_msg(msg_bytes)
        if not hit:
            return jsonify({"error": "no_excel_attachment_found"}), 400

        att_name, att_bytes, att_mime = hit
        save_name = (name_ovr or att_name or "attachment.xlsx").strip()
        if not save_name.lower().endswith((".xlsx", ".xlsm", ".xls", ".csv")):
            save_name += ".xlsx"

        new_tid = save_ticket({
            "type": "base64",
            "fileName": save_name,
            "mime": att_mime or "application/octet-stream",
            "data": base64.b64encode(att_bytes).decode("ascii")
        }, ttl=DEFAULT_TICKET_TTL)
        return jsonify({"ticket": new_tid})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===============================
# API：（組織用）OneDrive メタ
# ===============================
@app.get("/api/drive/item")
def api_drive_item():
    item_id = request.args.get("id", "")
    if not item_id:
        return jsonify({"error": "missing id"}), 400
    try:
        meta = graph_get_item_meta(item_id)
        return jsonify({"id": meta.get("id"), "name": meta.get("name"), "webUrl": meta.get("webUrl")})
    except requests.HTTPError as e:
        return jsonify({"error": "graph_http_error", "status": e.response.status_code, "detail": e.response.text}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===============================
# API：（組織用）アップロード（汎用：ticket 1件）
# ===============================
@app.post("/api/upload")
def api_upload():
    """
    form-data:
      ticket   : チケットID（text/base64/url/eml）
      folderId : 保存先フォルダの item.id
      fileName : 任意（上書き）
    """
    try:
        ticket   = request.form.get("ticket")
        folderId = request.form.get("folderId")
        name_ovr = request.form.get("fileName")

        if not ticket or not folderId:
            return jsonify({"error": "missing parameters"}), 400

        meta = redeem_ticket(ticket, consume=True)
        file_name, data_bytes, mime = materialize_bytes(meta)
        if name_ovr:
            file_name = name_ovr.strip() or file_name

        if len(data_bytes) <= SMALL_MAX_BYTES:
            r = graph_put_small_to_folder(folderId, file_name, mime, data_bytes)
        else:
            r = graph_put_chunked_to_folder(folderId, file_name, data_bytes)

        if r.status_code in (200, 201):
            j = r.json()
            return jsonify({"ok": True, "id": j.get("id"), "webUrl": j.get("webUrl"), "name": j.get("name")})
        else:
            return jsonify({"error": "graph_upload_failed", "status": r.status_code, "detail": r.text}), r.status_code

    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except requests.HTTPError as e:
        return jsonify({"error": "graph_http_error", "status": e.response.status_code, "detail": e.response.text}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===============================
# API：（組織用）.msg → Excel 抽出アップロード
# ===============================
@app.post("/api/upload-msg-xlsx")
def api_upload_msg_xlsx():
    """
    form-data:
      ticket   : .msg を指すチケット（type: base64/url/text いずれも可）
      folderId : 保存先フォルダの item.id
      fileName : 任意（保存名上書き。拡張子含む / 空なら添付名）
    """
    try:
        ticket   = request.form.get("ticket")
        folderId = request.form.get("folderId")
        name_ovr = request.form.get("fileName")

        if not ticket or not folderId:
            return jsonify({"error": "missing parameters"}), 400

        meta = redeem_ticket(ticket, consume=False)  # 原文別保存も想定し非消費
        _, msg_bytes, _ = materialize_bytes(meta)

        hit = _extract_first_excel_from_msg(msg_bytes)
        if not hit:
            return jsonify({"error": "no_excel_attachment_found"}), 400

        att_name, att_bytes, att_mime = hit
        save_name = (name_ovr or att_name).strip() or "attachment.xlsx"
        if not save_name.lower().endswith((".xlsx", ".xlsm", ".xls", ".csv")):
            save_name += ".xlsx"

        if len(att_bytes) <= SMALL_MAX_BYTES:
            r = graph_put_small_to_folder(folderId, save_name, att_mime, att_bytes)
        else:
            r = graph_put_chunked_to_folder(folderId, save_name, att_bytes)

        if r.status_code in (200, 201):
            j = r.json()
            return jsonify({"ok": True, "id": j.get("id"), "webUrl": j.get("webUrl"), "name": j.get("name")})
        else:
            return jsonify({"error": "graph_upload_failed", "status": r.status_code, "detail": r.text}), r.status_code

    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except requests.HTTPError as e:
        return jsonify({"error": "graph_http_error", "status": e.response.status_code, "detail": e.response.text}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===============================
# ローカル実行
# ===============================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
    