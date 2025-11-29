from flask import jsonify, request
import sqlite3

# ======================================================
# 🛡️ 安全登入 API 範例 (給組員 A 參考)
# 檔案名稱：secure_api.py
# 用途：示範如何使用 Prepared Statement 防禦 SQL Injection
# ======================================================

def login_api():
    # 1. 接收前端資料 (符合規定的 username / password)
    # 注意：這裡假設是用 Flask 框架，如果不一樣請告訴我
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # -----------------------------------------------------------
    # ❌ 不安全的寫法 (不要用這個！)
    # sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # -----------------------------------------------------------

    # ✅ 安全的寫法 (請用這個！)
    # 1. SQL 語句中只放問號 (?) 作為佔位符
    sql = "SELECT * FROM users WHERE username = ? AND password = ?"

    # 2. 將參數放在 execute 的第二個欄位 (Tuple)
    # 資料庫會強制將 username 和 password 視為「純文字」，而非 SQL 指令
    cursor.execute(sql, (username, password))
    
    user = cursor.fetchone()
    conn.close()

    # 3. 回傳格式維持不變 (JSON)
    if user:
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401