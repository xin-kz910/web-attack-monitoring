# 檔案位置：/vuln-site/app.py
import sqlite3
import os
import requests
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, Dict

# 🔗 A + B 串接：匯入偵測模組
from detector import detect_attack

# 建立 FastAPI 實例
app = FastAPI(title="Vulnerable Web App (Module A)")
DB_NAME = "vuln_site.db"

# --- 定義 Request Body 模型 (Pydantic) ---
class LoginRequest(BaseModel):
    username: str
    password: str

class SearchRequest(BaseModel):
    keyword: str

class ProxyRequest(BaseModel):
    url: str


# ========= A+B 串接：把 FastAPI Request 轉成 DetectionInput =========

def build_detection_input(request: Request, body: Optional[Dict] = None) -> dict:
    """
    轉成 B 模組 detect_attack 需要的格式：

    {
      "ip_address": "string",
      "url": "string",
      "http_method": "string",
      "params": dict,
      "body": dict,
      "user_agent": "string"
    }
    """
    if body is None:
        body = {}

    return {
        "ip_address": request.client.host if request.client else "",
        "url": request.url.path,                   # 例如 /api/login
        "http_method": request.method,            # GET / POST ...
        "params": dict(request.query_params),     # Query string
        "body": body,                             # 我們自己塞進去的 body
        "user_agent": request.headers.get("user-agent", "")
    }

# ========= 將攻擊發送給 Logging Service（C 模組） =========

LOGGING_SERVER_BASE = "http://127.0.0.1:8000"   # ← C 模組的網址與 port，依你們實際環境調整

def send_attack_to_logger(detection_result: dict, request: Request):
    """
    如果偵測到攻擊，將攻擊資料送給 Logging Service 的 /api/report-attack。
    """
    if not detection_result.get("is_attack"):
        return  # 沒偵測到攻擊不送

    try:
        url = f"{LOGGING_SERVER_BASE}/api/report-attack"

        payload = {
            "ip_address": detection_result.get("ip_address") or (request.client.host if request.client else ""),
            "url": str(request.url),
            "payload": detection_result.get("payload") or "",
            "attack_type": detection_result.get("attack_type") or "OTHER",
            "severity": detection_result.get("severity") or "LOW",
            "user_agent": request.headers.get("user-agent", "")
        }

        requests.post(url, json=payload, timeout=2)
        print("[LOGGING] Attack sent to logging service:", payload)

    except Exception as e:
        print("[LOGGING ERROR] 無法送到 Logging Service:", e)


# --- 資料庫初始化 ---
# 啟動時自動建立 users 表並插入測試帳號 
def init_db():
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)  # 重置資料庫

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    # 插入測試帳號
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin', 'admin')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')")
    
    conn.commit()
    conn.close()
    print("[INFO] 資料庫初始化完成 (FastAPI ver.)")

init_db()

# --- 漏洞 API 實作 ---

# root 路由回傳 login.html
@app.get("/")
async def root():
    return FileResponse("login.html")

# dashboard 路由
@app.get("/dashboard")
async def dashboard():
    return FileResponse("dashboard.html")


# 【漏洞 1 & 4】SQL Injection & Brute Force
# 目標：POST /api/login
# 說明：使用 f-string 拼接 SQL，導致 ' OR '1'='1 可繞過驗證
@app.post("/api/login")
async def login(request: Request, data: LoginRequest):
    # --- 先做攻擊偵測 ---
    detection_input = build_detection_input(
        request,
        body={"username": data.username, "password": data.password}
    )
    detection_result = detect_attack(detection_input)
    print("[DETECT] /api/login ->", detection_result)

    send_attack_to_logger(detection_result, request)


    if detection_result.get("should_block"):
        return JSONResponse(
            status_code=403,
            content={
                "message": "Blocked by WAF (login)",
                "attack_type": detection_result.get("attack_type"),
                "severity": detection_result.get("severity"),
                "payload": detection_result.get("payload"),
            }
        )

    # --- 原本不安全的登入邏輯 ---
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 錯誤寫法：直接將 Pydantic 驗證過的字串拼接到 SQL 中
    sql = f"SELECT * FROM users WHERE username = '{data.username}' AND password = '{data.password}'"
    
    print(f"[DEBUG] SQL Executed: {sql}")  # 讓你在後台看到攻擊語句

    try:
        cursor.execute(sql)
        user = cursor.fetchone()
    except Exception as e:
        conn.close()
        return JSONResponse(status_code=500, content={"error": str(e)})

    conn.close()

    if user:
        # 登入成功
        return {
            "message": "Login successful",
            "user_id": user[0],
            "role": user[3]
        }
    else:
        # 登入失敗 (無鎖定機制 -> 造成 Brute Force 漏洞)
        return JSONResponse(status_code=401, content={"message": "Login failed"})


# 【漏洞 2】XSS (Cross-Site Scripting)
# 目標：POST /api/search
# 說明：直接回傳 HTML，未經過濾
@app.post("/api/search", response_class=HTMLResponse)
async def search(request: Request, data: SearchRequest):
    # --- 先做攻擊偵測 ---
    detection_input = build_detection_input(
        request,
        body={"keyword": data.keyword}
    )
    detection_result = detect_attack(detection_input)
    print("[DETECT] /api/search ->", detection_result)

    send_attack_to_logger(detection_result, request)

    if detection_result.get("should_block"):
        # 被判定為攻擊時直接擋下
        return HTMLResponse(
            content=f"<h2>搜尋請求已被阻擋：疑似 {detection_result.get('attack_type')}</h2>",
            status_code=403
        )

    # --- 原本不安全的回傳方式 ---
    unsafe_html = f"<h2>搜尋結果： {data.keyword} </h2>"
    # 使用 HTMLResponse 模擬後端直接渲染頁面 (Server-Side Rendering)
    return unsafe_html


# 【漏洞 3】Path Traversal (目錄遍歷)
# 目標：GET /api/file
# 說明：未檢查 filename 是否包含 "../"，可讀取系統檔案
@app.get("/api/file")
async def get_file(request: Request, filename: str):
    # --- 先做攻擊偵測 ---
    detection_input = build_detection_input(request)
    detection_result = detect_attack(detection_input)
    print("[DETECT] /api/file ->", detection_result)

    send_attack_to_logger(detection_result, request)

    if detection_result.get("should_block"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "Blocked by WAF (file access)",
                "attack_type": detection_result.get("attack_type"),
                "payload": detection_result.get("payload"),
            }
        )

    # --- 原本不安全的檔案讀取 ---
    try:
        # 錯誤寫法：直接 open 使用者提供的路徑
        # 攻擊：/api/file?filename=app.py 或 ../../../etc/passwd
        if not os.path.exists(filename):
            return JSONResponse(status_code=404, content={"error": "File not found"})
             
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response(content=content, media_type="text/plain")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# 【漏洞 6】SSRF (Server-Side Request Forgery)
# 目標：POST /api/proxy
# 說明：Server 代替使用者發請求，未檢查是否為內網 IP
@app.post("/api/proxy")
def proxy(request: Request, data: ProxyRequest):
    target_url = data.url

    # --- 先做攻擊偵測 ---
    detection_input = build_detection_input(
        request,
        body={"url": target_url}
    )
    detection_result = detect_attack(detection_input)
    print("[DETECT] /api/proxy ->", detection_result)

    send_attack_to_logger(detection_result, request)

    if detection_result.get("should_block"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "Blocked by WAF (SSRF)",
                "attack_type": detection_result.get("attack_type"),
                "payload": detection_result.get("payload"),
            }
        )

    # --- 原本不安全的 SSRF 邏輯 ---
    try:
        print(f"[DEBUG] Server fetching: {target_url}")
        resp = requests.get(target_url, timeout=3)
        return {
            "status_code": resp.status_code,
            "sample_content": resp.text[:100]  # 回傳前100字
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# 【漏洞 5】Suspicious User-Agent
# 這是一個被動漏洞，FastAPI 本身不擋任何 UA。
# 只要有 request 帶著例如 "sqlmap"、"curl" 等 UA，
# 在 build_detection_input + detect_attack 的流程中就會被標記為 SUSPICIOUS_UA。

if __name__ == "__main__":
    import uvicorn
    # 啟動伺服器，host 0.0.0.0 允許外部連線
    uvicorn.run(app, host="0.0.0.0", port=5000)
