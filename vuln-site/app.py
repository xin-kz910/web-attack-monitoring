# 檔案位置：/vuln-site/app.py
import sqlite3
import os
import requests
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional

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

# --- 資料庫初始化 ---
# 啟動時自動建立 users 表並插入測試帳號 
def init_db():
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME) # 重置資料庫

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
# 目標：POST /api/login [cite: 201]
# 說明：使用 f-string 拼接 SQL，導致 ' OR '1'='1 可繞過驗證
@app.post("/api/login")
async def login(data: LoginRequest):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # 錯誤寫法：直接將 Pydantic 驗證過的字串拼接到 SQL 中
    sql = f"SELECT * FROM users WHERE username = '{data.username}' AND password = '{data.password}'"
    
    print(f"[DEBUG] SQL Executed: {sql}") # 讓你在後台看到攻擊語句

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
async def search(data: SearchRequest):
    # 錯誤寫法：將使用者輸入直接放入 HTML 字串
    # 如果 data.keyword 是 "<script>alert('XSS')</script>"，瀏覽器會執行它
    unsafe_html = f"<h2>搜尋結果： {data.keyword} </h2>"
    
    # 使用 HTMLResponse 模擬後端直接渲染頁面 (Server-Side Rendering)
    return unsafe_html


# 【漏洞 3】Path Traversal (目錄遍歷)
# 目標：GET /api/file
# 說明：未檢查 filename 是否包含 "../"，可讀取系統檔案
@app.get("/api/file")
async def get_file(filename: str):
    # 錯誤寫法：直接 open 使用者提供的路徑
    # 攻擊：/api/file?filename=app.py 或 ../../../etc/passwd
    try:
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
async def proxy(data: ProxyRequest):
    target_url = data.url
    
    # 錯誤寫法：沒有檢查 target_url 是否指向 localhost 或 192.168.x.x
    try:
        print(f"[DEBUG] Server fetching: {target_url}")
        resp = requests.get(target_url, timeout=3)
        return {
            "status_code": resp.status_code,
            "sample_content": resp.text[:100] # 回傳前100字
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# 【漏洞 5】Suspicious User-Agent
# 這是一個被動漏洞。FastAPI 預設不會阻擋任何 User-Agent。
# 只要攻擊者用 SQLMap 或 Nmap 掃描這個 API，
# 你的 B 組員 (Detection) 應該要在 Middleware 偵測到它。
# 這裡不需要寫額外程式碼，只需要讓 API 活著即可。

if __name__ == "__main__":
    import uvicorn
    # 啟動伺服器，host 0.0.0.0 允許外部連線
    uvicorn.run(app, host="0.0.0.0", port=5000)