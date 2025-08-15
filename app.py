# import os, io, time, requests
# from flask import Flask, request, jsonify, redirect
# from email.message import EmailMessage
# from email.utils import formatdate
# from datetime import datetime
# from dotenv import load_dotenv
# from urllib.parse import quote  # ← 追加

# # .env 読み込み
# load_dotenv()

# app = Flask(__name__)

# # ===== Azure OAuth / Graph 設定 =====
# CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
# CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
# TENANT = os.getenv("AZURE_TENANT", "common")
# REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:5000/callback")
# SCOPE = "offline_access Files.ReadWrite"

# AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
# TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
# GRAPH = "https://graph.microsoft.com/v1.0"
# DEFAULT_SAVE_DIR = os.getenv("DEFAULT_SAVE_DIR", "/AI/answers")

# TOKENS = {"access_token": None, "refresh_token": None, "exp": 0}

# def save_tokens(j):
#     TOKENS["access_token"] = j["access_token"]
#     TOKENS["refresh_token"] = j.get("refresh_token", TOKENS.get("refresh_token"))
#     TOKENS["exp"] = time.time() + int(j.get("expires_in", 3600)) - 60

# def need_refresh():
#     return not TOKENS["access_token"] or time.time() >= TOKENS["exp"]

# def refresh_if_needed():
#     if not need_refresh():
#         return
#     if not TOKENS["refresh_token"]:
#         raise RuntimeError("Not authenticated yet. Open /login first.")
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

# # ===== OAuth =====
# @app.get("/login")
# def login():
#     url = (
#         f"{AUTHZ}?client_id={CLIENT_ID}"
#         f"&response_type=code&redirect_uri={REDIRECT_URI}"
#         f"&scope={SCOPE}"
#     )
#     return redirect(url)

# @app.get("/callback")
# def callback():
#     code = request.args.get("code")
#     data = {
#         "client_id": CLIENT_ID,
#         "client_secret": CLIENT_SECRET,
#         "grant_type": "authorization_code",
#         "code": code,
#         "redirect_uri": REDIRECT_URI,
#     }
#     r = requests.post(TOKEN, data=data, timeout=30)
#     r.raise_for_status()
#     save_tokens(r.json())
#     return "OAuth OK! トークン保存済み。/eml/upload をPOSTしてね。"

# # ===== OneDriveユーティリティ =====
# def ensure_folder(path: str):
#     if not path or path == "/":
#         return
#     segs = [s for s in path.strip("/").split("/") if s]
#     parent = "root"
#     headers = {"Authorization": f"Bearer {TOKENS['access_token']}"}
#     for seg in segs:
#         quoted_name = quote(f'"{seg}"')  # ← "test-eml" を URLエンコード
#         url = f"{GRAPH}/me/drive/{parent}/children?$filter=name eq {quoted_name}"
#         r = requests.get(url, headers=headers, timeout=20)
#         r.raise_for_status()
#         items = r.json().get("value", [])
#         if items:
#             parent = f"items/{items[0]['id']}"
#         else:
#             create = f"{GRAPH}/me/drive/{parent}/children"
#             payload = {"name": seg, "folder": {}, "@microsoft.graph.conflictBehavior": "rename"}
#             cr = requests.post(create, headers={**headers, "Content-Type": "application/json"},
#                                json=payload, timeout=20)
#             cr.raise_for_status()
#             parent = f"items/{cr.json()['id']}"

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

# # ===== .eml 生成 → OneDrive保存 =====
# @app.post("/eml/upload")
# def upload_eml():
#     try:
#         refresh_if_needed()
#     except Exception as e:
#         return jsonify({"error": f"Auth required: {e}. ブラウザで /login を開いて許可してね"}), 401

#     data = request.get_json(force=True) or {}
#     subject = data.get("subject", "LLM Output")
#     from_addr = data.get("from_addr", "noreply@example.com")
#     to_addrs = data.get("to_addrs") or ["user@example.com"]
#     body_text = data.get("body_text", "")
#     body_html = data.get("body_html")
#     save_dir = data.get("save_dir") or DEFAULT_SAVE_DIR
#     base = data.get("filename") or f"llm_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
#     filename = base + ".eml"

#     eml = build_eml_bytes(subject, from_addr, to_addrs, body_text, body_html)
#     ensure_folder(save_dir)

#     url = f"{GRAPH}/me/drive/root:{save_dir}/{filename}:/content"
#     headers = {"Authorization": f"Bearer {TOKENS['access_token']}",
#                "Content-Type": "message/rfc822; charset=utf-8"}
#     r = requests.put(url, headers=headers, data=eml, timeout=30)
#     if r.status_code == 401:
#         refresh_if_needed()
#         headers["Authorization"] = f"Bearer {TOKENS['access_token']}"
#         r = requests.put(url, headers=headers, data=eml, timeout=30)
#     r.raise_for_status()
#     info = r.json()
#     return jsonify({"web_url": info.get("webUrl"), "file_id": info.get("id"), "name": info.get("name")})

# @app.get("/")
# def health():
#     return "OK"


import os, time, json, requests
from flask import Flask, request, jsonify, redirect
from email.message import EmailMessage
from email.utils import formatdate
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import quote

# .env
load_dotenv()

app = Flask(__name__)

# ===== Azure OAuth / Graph 設定 =====
CLIENT_ID = os.getenv("CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
TENANT = os.getenv("AZURE_TENANT", "common")
REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:5000/callback")
SCOPE = "offline_access Files.ReadWrite"
GRAPH = "https://graph.microsoft.com/v1.0"
AUTHZ = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize"
TOKEN = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

DEFAULT_SAVE_DIR = os.getenv("DEFAULT_SAVE_DIR", "/AI/answers")

# 任意（/token/export用の簡易保護）
ADMIN_KEY = os.getenv("ADMIN_KEY")

# ===== トークン（無料運用：refresh_token は環境変数から） =====
TOKENS = {
    "access_token": None,
    "refresh_token": os.getenv("REFRESH_TOKEN"),
    "exp": 0
}

def save_tokens(j: dict):
    TOKENS["access_token"] = j["access_token"]
    if j.get("refresh_token"):
        TOKENS["refresh_token"] = j["refresh_token"]
    TOKENS["exp"] = time.time() + int(j.get("expires_in", 3600)) - 60
    return {"access_token": "stored", "refresh_token": "updated" if j.get("refresh_token") else "unchanged"}

def need_refresh() -> bool:
    return not TOKENS["access_token"] or time.time() >= TOKENS["exp"]

def refresh_if_needed():
    if not need_refresh():
        return
    if not TOKENS["refresh_token"]:
        raise RuntimeError("Not authenticated yet. Set REFRESH_TOKEN or open /login first.")
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": TOKENS["refresh_token"],
        "redirect_uri": REDIRECT_URI,
    }
    r = requests.post(TOKEN, data=data, timeout=30)
    if not r.ok:
        app.logger.error(f"[Graph] refresh error: {r.status_code} {r.text}")
    r.raise_for_status()
    save_tokens(r.json())

# ===== OAuth =====
@app.get("/login")
def login():
    url = (
        f"{AUTHZ}?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={quote(REDIRECT_URI, safe='')}"
        f"&scope={quote(SCOPE, safe=' ')}"
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
    <p>保存後に再起動すると以後は自動更新（90日未使用で失効）。</p>
    """
    return html, 200

@app.get("/token/export")
def token_export():
    if ADMIN_KEY and request.headers.get("X-Admin-Key") != ADMIN_KEY:
        return "forbidden", 403
    return jsonify({
        "refresh_token": TOKENS.get("refresh_token") or os.getenv("REFRESH_TOKEN"),
        "note": "Set this as REFRESH_TOKEN env on Render."
    })

@app.get("/warmup")
def warmup():
    try:
        refresh_if_needed()
        return jsonify({"ok": True, "has_access_token": bool(TOKENS["access_token"])})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 401

# ===== OneDriveユーティリティ（パスアドレッシング & 例外をJSON化） =====
def ensure_folder(path: str):
    """
    /me/drive/{parent}:/{child} で存在確認→なければ /children で作成。
    ここでは例外を投げず呼び出し側で扱えるように辞書で返す。
    """
    if not path or path == "/":
        return {"ok": True}

    segs = [s for s in path.strip("/").split("/") if s]
    parent = "root"
    headers = {"Authorization": f"Bearer {TOKENS['access_token']}"}

    for seg in segs:
        get_url = f"{GRAPH}/me/drive/{parent}:/{quote(seg, safe='')}"
        gr = requests.get(get_url, headers=headers, timeout=20)
        if gr.status_code == 200:
            parent = f"items/{gr.json()['id']}"
            continue
        if gr.status_code != 404:
            return {"ok": False, "stage": "get", "status": gr.status_code, "detail": gr.text}

        create_url = f"{GRAPH}/me/drive/{parent}/children"
        payload = {"name": seg, "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}
        cr = requests.post(create_url, headers={**headers, "Content-Type": "application/json"},
                           json=payload, timeout=20)
        if not cr.ok:
            return {"ok": False, "stage": "create", "status": cr.status_code, "detail": cr.text}
        parent = f"items/{cr.json()['id']}"

    return {"ok": True}

def build_eml_bytes(subject, from_addr, to_addrs, body_text="", body_html=None, date_str=None) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject or "LLM Output"
    msg["From"] = from_addr or "noreply@example.com"
    msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else to_addrs
    msg["Date"] = date_str or formatdate(localtime=True)
    msg["MIME-Version"] = "1.0"
    if body_html:
        msg.set_content(body_text or "", subtype="plain", charset="utf-8")
        msg.add_alternative(body_html, subtype="html", charset="utf-8")
    else:
        msg.set_content(body_text or "", subtype="plain", charset="utf-8")
    return msg.as_bytes()

# ===== .eml 生成 → OneDrive 保存 =====
@app.post("/eml/upload")
def upload_eml():
    # 認証（401はJSONで返す）
    try:
        refresh_if_needed()
    except Exception as e:
        return jsonify({"error": f"Auth required: {e}. /login でrefresh_token取得→Renderの環境変数に保存してね"}), 401

    # 入力取り出し
    data = request.get_json(force=True) or {}
    subject = data.get("subject", "LLM Output")
    from_addr = data.get("from_addr", "noreply@example.com")
    to_addrs = data.get("to_addrs") or ["user@example.com"]
    body_text = data.get("body_text", "")
    body_html = data.get("body_html")
    save_dir = data.get("save_dir") or DEFAULT_SAVE_DIR
    base = data.get("filename") or f"llm_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    filename = base + ".eml"

    # パス整形
    if not save_dir.startswith("/"):
        save_dir = "/" + save_dir
    save_dir = save_dir.rstrip("/")

    # EML生成
    eml = build_eml_bytes(subject, from_addr, to_addrs, body_text, body_html)

    # フォルダ作成（失敗時は詳細をJSON返却）
    fol = ensure_folder(save_dir)
    if not fol.get("ok"):
        return jsonify({"error": "ensure_folder failed", **fol}), 400

    # アップロード（Content-Type はより汎用的に）
    path_for_url = quote(f"{save_dir}/{filename}", safe="/")
    url = f"{GRAPH}/me/drive/root:{path_for_url}:/content"
    headers = {
        "Authorization": f"Bearer {TOKENS['access_token']}",
        "Content-Type": "application/octet-stream"
    }
    r = requests.put(url, headers=headers, data=eml, timeout=30)
    if r.status_code == 401:
        # 途中失効のワンモアトライ
        refresh_if_needed()
        headers["Authorization"] = f"Bearer {TOKENS['access_token']}"
        r = requests.put(url, headers=headers, data=eml, timeout=30)

    if not r.ok:
        return jsonify({"error": "upload failed", "status": r.status_code, "detail": r.text}), r.status_code

    info = r.json()
    return jsonify({"web_url": info.get("webUrl"), "file_id": info.get("id"), "name": info.get("name")})

@app.get("/")
def health():
    return "OK"


# === 追加：診断用エンドポイント ===
@app.get("/diag")
def diag():
    try:
        refresh_if_needed()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 401

    hdrs = {"Authorization": f"Bearer {TOKENS['access_token']}"}
    me = requests.get(f"{GRAPH}/me", headers=hdrs, timeout=20)
    drive = requests.get(f"{GRAPH}/me/drive", headers=hdrs, timeout=20)

    info = {
        "ok": me.ok and drive.ok,
        "me_status": me.status_code,
        "drive_status": drive.status_code,
        "me": me.json() if me.ok else me.text,
        "drive": drive.json() if drive.ok else drive.text
    }
    return jsonify(info), (200 if info["ok"] else 400)

@app.get("/logout")
def logout():
    """手動でトークンを破棄（無料版ではメモリだけ）"""
    TOKENS.update({"access_token": None, "refresh_token": None, "exp": 0})
    return jsonify({"ok": True, "message": "Tokens cleared. Please re-login via /login."})
