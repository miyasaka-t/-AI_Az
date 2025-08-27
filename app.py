# import os, time, json, base64, requests
# from flask import Flask, request, jsonify, redirect
# from email.message import EmailMessage
# from email.utils import formatdate
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import quote

# # .env 読み込み
# load_dotenv()

# app = Flask(__name__)

# # ===== Azure OAuth / Graph 設定 =====
# # CLIENT_ID/SECRET がなければ AZURE_CLIENT_ID/SECRET を読む（どちらか片方に統一推奨）
# CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
# CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
# TENANT = os.getenv("AZURE_TENANT", "common")  # 個人固定したい場合は 'consumers' をENVで設定
# REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:5000/callback")
# SCOPE = "offline_access Files.ReadWrite"

# GRAPH = "https://graph.microsoft.com/v1.0"
# AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
# TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# DEFAULT_SAVE_DIR = os.getenv("DEFAULT_SAVE_DIR", "/AI/answers")

# # 任意（/token/export用の簡易保護）
# ADMIN_KEY = os.getenv("ADMIN_KEY")

# # ===== トークン（無料運用：refresh_token は環境変数から読込。保存はしない） =====
# TOKENS = {
#     "access_token": None,
#     "refresh_token": os.getenv("REFRESH_TOKEN"),
#     "exp": 0
# }

# def save_tokens(j: dict):
#     TOKENS["access_token"] = j["access_token"]
#     if j.get("refresh_token"):
#         TOKENS["refresh_token"] = j["refresh_token"]
#     TOKENS["exp"] = time.time() + int(j.get("expires_in", 3600)) - 60
#     return {"access_token": "stored", "refresh_token": "updated" if j.get("refresh_token") else "unchanged"}

# def need_refresh() -> bool:
#     return not TOKENS["access_token"] or time.time() >= TOKENS["exp"]

# def refresh_if_needed():
#     if not need_refresh():
#         return
#     if not TOKENS["refresh_token"]:
#         raise RuntimeError("Not authenticated yet. Set REFRESH_TOKEN or open /login first.")
#     data = {
#         "client_id": CLIENT_ID,
#         "client_secret": CLIENT_SECRET,
#         "grant_type": "refresh_token",
#         "refresh_token": TOKENS["refresh_token"],
#         "redirect_uri": REDIRECT_URI,
#     }
#     r = requests.post(TOKEN, data=data, timeout=30)
#     if not r.ok:
#         app.logger.error(f"[Graph] refresh error: {r.status_code} {r.text}")
#     r.raise_for_status()
#     save_tokens(r.json())

# # ===== OAuth =====
# @app.get("/login")
# def login():
#     # 事故防止のため毎回アカウント選択を強制。個人寄せしたいときは domain_hint=consumers。
#     url = (
#         f"{AUTHZ}?client_id={CLIENT_ID}"
#         f"&response_type=code"
#         f"&redirect_uri={quote(REDIRECT_URI, safe='')}"
#         f"&scope={quote(SCOPE, safe=' ')}"
#         f"&prompt=select_account&domain_hint=consumers"
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
#     <p>保存後にサービス再起動すると、以後は自動更新（ただし90日未使用で失効）。</p>
#     """
#     return html, 200

# @app.get("/logout")
# def logout():
#     """手動でトークンを破棄（無料版ではメモリのみ）"""
#     TOKENS.update({"access_token": None, "refresh_token": None, "exp": 0})
#     return jsonify({"ok": True, "message": "Tokens cleared. Please re-login via /login."})

# @app.get("/token/export")
# def token_export():
#     if ADMIN_KEY and request.headers.get("X-Admin-Key") != ADMIN_KEY:
#         return "forbidden", 403
#     return jsonify({
#         "refresh_token": TOKENS.get("refresh_token") or os.getenv("REFRESH_TOKEN"),
#         "note": "Set this as REFRESH_TOKEN env on Render."
#     })

# @app.get("/warmup")
# def warmup():
#     try:
#         refresh_if_needed()
#         return jsonify({"ok": True, "has_access_token": bool(TOKENS["access_token"])})
#     except Exception as e:
#         return jsonify({"ok": False, "error": str(e)}), 401

# # ===== OneDriveユーティリティ（パスアドレッシング & 例外をJSON化） =====
# def ensure_folder(path: str):
#     """
#     /me/drive/{parent}:/{child} で存在確認→なければ /children で作成。
#     ここでは例外を投げず辞書で返す（呼び出し側でJSON化して返せるように）。
#     """
#     if not path or path == "/":
#         return {"ok": True}

#     segs = [s for s in path.strip("/").split("/") if s]
#     parent = "root"
#     headers = {"Authorization": f"Bearer {TOKENS['access_token']}"}

#     for seg in segs:
#         get_url = f"{GRAPH}/me/drive/{parent}:/{quote(seg, safe='')}"
#         gr = requests.get(get_url, headers=headers, timeout=20)
#         if gr.status_code == 200:
#             parent = f"items/{gr.json()['id']}"
#             continue
#         if gr.status_code != 404:
#             return {"ok": False, "stage": "get", "status": gr.status_code, "detail": gr.text}

#         create_url = f"{GRAPH}/me/drive/{parent}/children"
#         payload = {"name": seg, "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}
#         cr = requests.post(create_url, headers={**headers, "Content-Type": "application/json"},
#                            json=payload, timeout=20)
#         if not cr.ok:
#             return {"ok": False, "stage": "create", "status": cr.status_code, "detail": cr.text}
#         parent = f"items/{cr.json()['id']}"

#     return {"ok": True}

# def build_eml_bytes(subject, from_addr, to_addrs, body_text="", body_html=None, date_str=None) -> bytes:
#     msg = EmailMessage()
#     msg["Subject"] = subject or "LLM Output"
#     msg["From"] = from_addr or "noreply@example.com"
#     msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else to_addrs
#     msg["Date"] = date_str or formatdate(localtime=True)
#     msg["MIME-Version"] = "1.0"
#     if body_html:
#         msg.set_content(body_text or "", subtype="plain", charset="utf-8")
#         msg.add_alternative(body_html, subtype="html", charset="utf-8")
#     else:
#         msg.set_content(body_text or "", subtype="plain", charset="utf-8")
#     return msg.as_bytes()

# # ===== .eml 生成 → OneDrive 保存 =====
# @app.post("/eml/upload")
# def upload_eml():
#     # 認証（401はJSONで返す）
#     try:
#         refresh_if_needed()
#     except Exception as e:
#         return jsonify({"error": f"Auth required: {e}. /login でrefresh_token取得→Renderの環境変数に保存してね"}), 401

#     # 入力取り出し
#     data = request.get_json(force=True) or {}
#     subject = data.get("subject", "LLM Output")
#     from_addr = data.get("from_addr", "noreply@example.com")
#     to_addrs = data.get("to_addrs") or ["user@example.com"]
#     body_text = data.get("body_text", "")
#     body_html = data.get("body_html")
#     save_dir = data.get("save_dir") or DEFAULT_SAVE_DIR
#     base = data.get("filename") or f"llm_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
#     filename = base + ".eml"

#     # パス整形
#     if not save_dir.startswith("/"):
#         save_dir = "/" + save_dir
#     save_dir = save_dir.rstrip("/")

#     # EML生成
#     eml = build_eml_bytes(subject, from_addr, to_addrs, body_text, body_html)

#     # フォルダ作成（失敗時は詳細をJSON返却）
#     fol = ensure_folder(save_dir)
#     if not fol.get("ok"):
#         return jsonify({"error": "ensure_folder failed", **fol}), 400

#     # アップロード（Content-Type はより汎用的に）
#     path_for_url = quote(f"{save_dir}/{filename}", safe="/")
#     url = f"{GRAPH}/me/drive/root:{path_for_url}:/content"
#     headers = {
#         "Authorization": f"Bearer {TOKENS['access_token']}",
#         "Content-Type": "application/octet-stream"
#     }
#     r = requests.put(url, headers=headers, data=eml, timeout=30)
#     if r.status_code == 401:
#         # 途中失効のワンモアトライ
#         refresh_if_needed()
#         headers["Authorization"] = f"Bearer {TOKENS['access_token']}"
#         r = requests.put(url, headers=headers, data=eml, timeout=30)

#     if not r.ok:
#         return jsonify({"error": "upload failed", "status": r.status_code, "detail": r.text}), r.status_code

#     info = r.json()
#     return jsonify({"web_url": info.get("webUrl"), "file_id": info.get("id"), "name": info.get("name")})

# @app.get("/")
# def health():
#     return "OK"

# # === 診断：どこに向いてるか（個人/組織） ===
# @app.get("/diag")
# def diag():
#     try:
#         refresh_if_needed()
#     except Exception as e:
#         return jsonify({"ok": False, "error": str(e)}), 401

#     hdrs = {"Authorization": f"Bearer {TOKENS['access_token']}"}
#     me = requests.get(f"{GRAPH}/me", headers=hdrs, timeout=20)
#     drive = requests.get(f"{GRAPH}/me/drive", headers=hdrs, timeout=20)

#     info = {
#         "ok": me.ok and drive.ok,
#         "me_status": me.status_code,
#         "drive_status": drive.status_code,
#         "drive_type": (drive.json().get("driveType") if drive.ok else None),
#         "me_tenant": (me.json().get("userPrincipalName") if me.ok else None)
#     }
#     return jsonify(info), (200 if info["ok"] else 400)

# # === 診断：アクセストークンのテナントID（tid）を見る ===
# def _jwt_parts(token: str):
#     try:
#         head, payload, _ = token.split(".")
#         pad = lambda s: s + "=" * (-len(s) % 4)
#         return (json.loads(base64.urlsafe_b64decode(pad(head)).decode()),
#                 json.loads(base64.urlsafe_b64decode(pad(payload)).decode()))
#     except Exception as e:
#         return None, {"error": str(e)}

# @app.get("/tokeninfo")
# def tokeninfo():
#     try:
#         refresh_if_needed()
#     except Exception as e:
#         return jsonify({"ok": False, "error": str(e)}), 401
#     h, p = _jwt_parts(TOKENS["access_token"])
#     return jsonify({
#         "ok": True,
#         "tid": p.get("tid"),
#         "upn": p.get("upn") or p.get("preferred_username"),
#         "note": "tid == 9188040d-6c67-4c5b-b112-36a304b66dad なら個人(MSA)テナント"
#     })


# ＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝



# import os, time, json, base64, secrets, requests
# from flask import Flask, request, jsonify, redirect, make_response
# from flask_cors import CORS
# from email.message import EmailMessage
# from email.utils import formatdate
# from datetime import datetime
# from urllib.parse import quote

# app = Flask(__name__)
# CORS(app, resources={r"/api/*": {"origins": "*"}, r"/tickets/*": {"origins": "*"}})

# # ===== Azure OAuth / Graph (OneDrive 個人用/MSA向け) =====
# CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
# CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
# TENANT = os.getenv("AZURE_TENANT", "consumers")  # ← 個人用なら "consumers"
# REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:5000/callback")
# SCOPE = "offline_access Files.ReadWrite"         # 個人用の保存に必要十分

# GRAPH = "https://graph.microsoft.com/v1.0"
# AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
# TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# # 簡易メモリ・トークン保管（REFRESH_TOKEN は環境変数で永続）
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

# # ===== EML生成（任意：payload.type='eml'用） =====
# def build_eml_bytes(subject, from_addr, to_addrs, body_text="", body_html=None, date_str=None) -> bytes:
#     msg = EmailMessage()
#     msg["Subject"] = subject or "LLM Output"
#     msg["From"] = from_addr or "noreply@example.com"
#     msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else (to_addrs or "")
#     msg["Date"] = date_str or formatdate(localtime=True)
#     if body_html:
#         msg.set_content(body_text or "", subtype="plain", charset="utf-8")
#         msg.add_alternative(body_html, subtype="html", charset="utf-8")
#     else:
#         msg.set_content(body_text or "", subtype="plain", charset="utf-8")
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
#         fn = j.get("fileName") or f"llm_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
#         mime = j.get("mime") or "application/octet-stream"
#         payload = j.get("payload") or {"type":"text", "body":""}
#         ttl = int(j.get("ttlSec", 600))
#         once = bool(j.get("once", True))
#         tid, ttl_sec = issue_ticket(fn, mime, payload, ttl, once)
#         return jsonify({"ticket": tid, "expiresIn": ttl_sec})
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
#         if not u: raise RuntimeError("payload.url missing")
#         r = requests.get(u, timeout=60)
#         r.raise_for_status()
#         return r.content
#     if t == "eml":
#         return build_eml_bytes(
#             subject=p.get("subject"),
#             from_addr=p.get("from"),
#             to_addrs=p.get("to") or ["user@example.com"],
#             body_text=p.get("text",""),
#             body_html=p.get("html")
#         )
#     raise RuntimeError(f"unsupported payload.type: {t}")

# # ===== OneDrive(個人) へアップロード（フォルダID基点）=====
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
#     sess = requests.post(sess_url, headers={"Authorization": f"Bearer {TOKENS['access_token']}"}, timeout=30)
#     if not sess.ok:
#         return sess
#     upload_url = sess.json()["uploadUrl"]
#     CHUNK = 10 * 1024 * 1024
#     size = len(data)
#     pos = 0
#     last = None
#     while pos < size:
#         chunk = data[pos:pos+CHUNK]
#         headers = {
#             "Content-Length": str(len(chunk)),
#             "Content-Range": f"bytes {pos}-{pos+len(chunk)-1}/{size}"
#         }
#         last = requests.put(upload_url, headers=headers, data=chunk, timeout=120)
#         if last.status_code not in (200, 201, 202):
#             break
#         pos += len(chunk)
#     return last

# @app.post("/api/upload")
# def api_upload():
#     """
#     front(onedrive.html) から:
#       ticket, folderId, (optional) fileName
#     """
#     try:
#         ticket   = request.form.get("ticket")
#         folder_id= request.form.get("folderId")
#         name_ovr = request.form.get("fileName")
#         if not all([ticket, folder_id]):
#             return jsonify({"error":"missing parameters"}), 400

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
#             return jsonify({"error":"graph upload failed","status":r.status_code,"detail":r.text}), r.status_code
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

# ＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝


# import os, time, json, base64, secrets, requests
# from flask import Flask, request, jsonify, redirect, make_response
# from flask_cors import CORS
# from email.message import EmailMessage
# from email.utils import formatdate
# from datetime import datetime
# from urllib.parse import quote

# app = Flask(__name__)
# CORS(app, resources={r"/api/*": {"origins": "*"}, r"/tickets/*": {"origins": "*"}})

# # ===== Azure OAuth / Graph (OneDrive 個人用/MSA向け) =====
# CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
# CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
# TENANT = os.getenv("AZURE_TENANT", "consumers")  # ← 個人用なら "consumers"
# REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:5000/callback")
# SCOPE = "offline_access Files.ReadWrite"         # 個人用の保存に必要十分

# GRAPH = "https://graph.microsoft.com/v1.0"
# AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
# TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# # 簡易メモリ・トークン保管（REFRESH_TOKEN は環境変数で永続）
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

# # ===== EML生成 =====
# def build_eml_bytes(subject, from_addr, to_addrs, body_text="", body_html=None, date_str=None) -> bytes:
#     msg = EmailMessage()
#     msg["Subject"] = subject or "LLM Output"
#     msg["From"] = from_addr or "noreply@example.com"
#     msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else (to_addrs or "")
#     msg["Date"] = date_str or formatdate(localtime=True)
#     if body_html:
#         msg.set_content(body_text or "", subtype="plain", charset="utf-8")
#         msg.add_alternative(body_html, subtype="html", charset="utf-8")
#     else:
#         msg.set_content(body_text or "", subtype="plain", charset="utf-8")
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

#         # fileName 未指定なら type に応じた拡張子を付与
#         ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
#         default_name = f"llm_{ts}.eml" if ptype == "eml" else f"llm_{ts}.txt"
#         fn = j.get("fileName") or default_name

#         # eml の場合は拡張子を強制
#         if ptype == "eml" and not fn.lower().endswith(".eml"):
#             fn = fn + ".eml"

#         # MIME 既定値
#         mime = j.get("mime")
#         if not mime:
#             mime = "message/rfc822" if ptype == "eml" else "application/octet-stream"

#         ttl = int(j.get("ttlSec", 600))
#         once = bool(j.get("once", True))
#         tid, ttl_sec = issue_ticket(fn, mime, payload, ttl, once)
#         return jsonify({"ticket": tid, "expiresIn": ttl_sec})
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
#         if not u: raise RuntimeError("payload.url missing")
#         r = requests.get(u, timeout=60)
#         r.raise_for_status()
#         return r.content
#     if t == "eml":
#         return build_eml_bytes(
#             subject=p.get("subject"),
#             from_addr=p.get("from"),
#             to_addrs=p.get("to") or ["user@example.com"],
#             body_text=p.get("text",""),
#             body_html=p.get("html"),
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
#         chunk = data[pos:pos+CHUNK]
#         headers = {
#             "Content-Length": str(len(chunk)),
#             "Content-Range": f"bytes {pos}-{pos+len(chunk)-1}/{size}"
#         }
#         last = requests.put(upload_url, headers=headers, data=chunk, timeout=120)
#         if last.status_code not in (200, 201, 202):
#             break
#         pos += len(chunk)
#     return last

# @app.post("/api/upload")
# def api_upload():
#     """
#     front(onedrive.html) から:
#       ticket, folderId, (optional) fileName
#     """
#     try:
#         ticket   = request.form.get("ticket")
#         folder_id= request.form.get("folderId")
#         name_ovr = request.form.get("fileName")
#         if not all([ticket, folder_id]):
#             return jsonify({"error":"missing parameters"}), 400

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
#             return jsonify({"error":"graph upload failed","status":r.status_code,"detail":r.text}), r.status_code
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400

#＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝＝
import os, time, json, base64, secrets, requests
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from email.message import EmailMessage
from email.utils import formatdate
from datetime import datetime
from urllib.parse import quote

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/tickets/*": {"origins": "*"}})

# ===== Azure OAuth / Graph (OneDrive 個人用/MSA向け) =====
CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
TENANT = os.getenv("AZURE_TENANT", "consumers")  # 個人用なら "consumers"
REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:5000/callback")
SCOPE = "offline_access Files.ReadWrite"         # 個人用の保存に必要十分

GRAPH = "https://graph.microsoft.com/v1.0"
AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

# ===== 簡易メモリ・トークン保管（REFRESH_TOKEN は環境変数で永続） =====
TOKENS = {"access_token": None, "refresh_token": os.getenv("REFRESH_TOKEN"), "exp": 0}

def save_tokens(j: dict):
    TOKENS["access_token"] = j["access_token"]
    if j.get("refresh_token"):
        TOKENS["refresh_token"] = j["refresh_token"]
    TOKENS["exp"] = time.time() + int(j.get("expires_in", 3600)) - 60

def need_refresh() -> bool:
    return not TOKENS["access_token"] or time.time() >= TOKENS["exp"]

def refresh_if_needed():
    if not need_refresh():
        return
    if not TOKENS["refresh_token"]:
        raise RuntimeError("Not authenticated. Set REFRESH_TOKEN or open /login.")
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": TOKENS["refresh_token"],
        "redirect_uri": REDIRECT_URI,
    }
    r = requests.post(TOKEN, data=data, timeout=30)
    r.raise_for_status()
    save_tokens(r.json())

# ===== OAuthフロー（個人用） =====
@app.get("/login")
def login():
    url = (
        f"{AUTHZ}?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={quote(REDIRECT_URI, safe='')}"
        f"&scope={quote(SCOPE, safe=' ')}"
        f"&prompt=select_account"
        f"&domain_hint=consumers"
    )
    return redirect(url)

@app.get("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "missing code", 400
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    r = requests.post(TOKEN, data=data, timeout=30)
    if not r.ok:
        return f"OAuth error: {r.status_code} {r.text}", 400
    token_info = r.json()
    save_tokens(token_info)

    rt = token_info.get("refresh_token", "")
    html = f"""
    <h3>OAuth OK</h3>
    <p>Render の Environment に <code>REFRESH_TOKEN</code> として保存してね。</p>
    <pre style="white-space: pre-wrap;">{rt}</pre>
    <p>保存後にサービス再起動すると、以後は自動更新（90日未使用で失効のことあり）。</p>
    """
    return html, 200

@app.get("/logout")
def logout():
    TOKENS.update({"access_token": None, "refresh_token": None, "exp": 0})
    return jsonify({"ok": True})

@app.get("/")
def health():
    return "OK"

# ===== EML生成 =====
def build_eml_bytes(subject, from_addr, to_addrs, body_text="", body_html=None, date_str=None) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject or "LLM Output"
    msg["From"] = from_addr or "noreply@example.com"
    msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else (to_addrs or "")
    msg["Date"] = date_str or formatdate(localtime=True)
    if body_html:
        msg.set_content(body_text or "", subtype="plain", charset="utf-8")
        msg.add_alternative(body_html, subtype="html", charset="utf-8")
    else:
        msg.set_content(body_text or "", subtype="plain", charset="utf-8")
    return msg.as_bytes()

# ===== チケット管理（メモリ／短命） =====
TICKETS = {}  # tid -> dict

def _now(): return int(time.time())

def issue_ticket(file_name: str, mime: str, payload: dict, ttl_sec: int = 600, once: bool = True):
    tid = secrets.token_urlsafe(24)
    TICKETS[tid] = {
        "file_name": file_name,
        "mime": mime or "application/octet-stream",
        "payload": payload,    # {"type":"text"|"base64"|"url"|"eml", ...}
        "expire_at": _now() + int(ttl_sec or 600),
        "used": False,
        "once": bool(once),
    }
    return tid, ttl_sec

def redeem_ticket(tid: str, consume: bool = False):
    meta = TICKETS.get(tid)
    if not meta:
        raise RuntimeError("ticket not found or expired")
    if _now() > meta["expire_at"]:
        TICKETS.pop(tid, None)
        raise RuntimeError("ticket expired")
    if meta["once"] and meta["used"] and consume:
        raise RuntimeError("ticket already used")
    if consume and meta["once"]:
        meta["used"] = True
    return meta

# ===== チケット作成 =====
@app.post("/tickets/create")
def tickets_create():
    """
    Dify から叩く:
    {
      "fileName": "Report_2025-08-26.txt",
      "mime": "text/plain",
      "payload": { "type":"text", "body":"<<LLM出力>>" },  # text/base64/url/eml に対応
      "ttlSec": 600,
      "once": true
    }
    """
    try:
        j = request.get_json(force=True) or {}
        payload = j.get("payload") or {"type": "text", "body": ""}
        ptype = (payload.get("type") or "text").lower()

        # fileName 未指定なら type に応じた拡張子を付与
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        default_name = f"llm_{ts}.eml" if ptype == "eml" else f"llm_{ts}.txt"
        fn = j.get("fileName") or default_name

        # eml の場合は拡張子を強制
        if ptype == "eml" and not fn.lower().endswith(".eml"):
            fn = fn + ".eml"

        # MIME 既定値
        mime = j.get("mime")
        if not mime:
            mime = "message/rfc822" if ptype == "eml" else "application/octet-stream"

        ttl = int(j.get("ttlSec", 600))
        once = bool(j.get("once", True))
        tid, ttl_sec = issue_ticket(fn, mime, payload, ttl, once)
        return jsonify({"ticket": tid, "expiresIn": ttl_sec})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===== チケット内容の確認用（消費しない Peek） =====
@app.get("/tickets/peek")
def tickets_peek():
    """
    クエリ: ?ticket=<ticket id>
    戻り値: {"fileName": "...", "mime":"...", "type":"eml|text|base64|url"}
    """
    try:
        tid = request.args.get("ticket", "")
        if not tid:
            return jsonify({"error": "missing ticket"}), 400
        meta = redeem_ticket(tid, consume=False)
        p = meta.get("payload") or {}
        return jsonify({
            "fileName": meta.get("file_name"),
            "mime": meta.get("mime"),
            "type": (p.get("type") or "text").lower()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ===== payload を bytes に実体化 =====
def materialize_bytes(meta: dict) -> bytes:
    p = meta["payload"] or {}
    t = (p.get("type") or "text").lower()
    if t == "text":
        return (p.get("body") or "").encode("utf-8")
    if t == "base64":
        return base64.b64decode(p.get("data") or "")
    if t == "url":
        u = p.get("href")
        if not u:
            raise RuntimeError("payload.url missing")
        r = requests.get(u, timeout=60)
        r.raise_for_status()
        return r.content
    if t == "eml":
        return build_eml_bytes(
            subject=p.get("subject"),
            from_addr=p.get("from"),
            to_addrs=p.get("to") or ["user@example.com"],
            body_text=p.get("text", ""),
            body_html=p.get("html"),
            date_str=p.get("date")
        )
    raise RuntimeError(f"unsupported payload.type: {t}")

# ===== OneDrive(個人) へアップロード =====
def graph_put_small_to_folder(folder_id: str, name: str, mime: str, data: bytes):
    refresh_if_needed()
    url = f"{GRAPH}/me/drive/items/{folder_id}:/{quote(name, safe='')}:/content"
    r = requests.put(url, headers={
        "Authorization": f"Bearer {TOKENS['access_token']}",
        "Content-Type": mime or "application/octet-stream"
    }, data=data, timeout=120)
    return r

def graph_put_chunked_to_folder(folder_id: str, name: str, data: bytes):
    refresh_if_needed()
    sess_url = f"{GRAPH}/me/drive/items/{folder_id}:/{quote(name, safe='')}:/createUploadSession"
    sess = requests.post(
        sess_url,
        headers={"Authorization": f"Bearer {TOKENS['access_token']}", "Content-Type": "application/json"},
        json={"item": {"@microsoft.graph.conflictBehavior": "replace", "name": name}},
        timeout=30
    )
    if not sess.ok:
        return sess
    upload_url = sess.json()["uploadUrl"]
    CHUNK = 10 * 1024 * 1024
    size = len(data)
    pos = 0
    last = None
    while pos < size:
        chunk = data[pos:pos + CHUNK]
        headers = {
            "Content-Length": str(len(chunk)),
            "Content-Range": f"bytes {pos}-{pos + len(chunk) - 1}/{size}"
        }
        last = requests.put(upload_url, headers=headers, data=chunk, timeout=120)
        if last.status_code not in (200, 201, 202):
            break
        pos += len(chunk)
    return last

# ===== アップロードAPI =====
@app.post("/api/upload")
def api_upload():
    """
    front(onedrive.html) から:
      ticket, folderId, (optional) fileName
    """
    try:
        ticket    = request.form.get("ticket")
        folder_id = request.form.get("folderId")
        name_ovr  = request.form.get("fileName")
        if not all([ticket, folder_id]):
            return jsonify({"error": "missing parameters"}), 400

        meta = redeem_ticket(ticket, consume=True)  # 使い捨て
        data = materialize_bytes(meta)
        name = name_ovr or meta["file_name"]
        mime = meta.get("mime", "application/octet-stream")

        # ~250MB以下は一発、超過は分割
        if len(data) <= 250 * 1024 * 1024:
            r = graph_put_small_to_folder(folder_id, name, mime, data)
        else:
            r = graph_put_chunked_to_folder(folder_id, name, data)

        if r.status_code in (200, 201):
            item = r.json()
            return jsonify({"ok": True, "id": item.get("id"), "webUrl": item.get("webUrl"), "name": item.get("name")})
        else:
            return jsonify({"error": "graph upload failed", "status": r.status_code, "detail": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 400
