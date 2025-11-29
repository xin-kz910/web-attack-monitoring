import sqlite3
import html
import os
import time
import socket
from urllib.parse import urlparse

# ==========================================
# 1. 🛡️ 防禦 SQL Injection (SQLi)
# ==========================================
def secure_login(username, password):
    # 模擬資料庫連線
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (username TEXT, password TEXT)')
    cursor.execute("INSERT INTO users VALUES ('admin', '123456')")
    
    # ✅ 安全寫法：使用 ? 作為佔位符
    sql = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(sql, (username, password))
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return "[SQLi防禦] 登入成功"
    else:
        return "[SQLi防禦] 登入失敗 (攻擊無效)"

# ==========================================
# 2. 🛡️ 防禦 XSS (跨站腳本攻擊)
# ==========================================
def clean_xss_input(user_text):
    # ✅ 安全寫法：將特殊符號轉義
    return html.escape(user_text)

# ==========================================
# 3. 🛡️ 防禦 Path Traversal (目錄遍歷)
# ==========================================
def read_secure_file(filename):
    # ✅ 安全寫法：只取檔名，去掉所有路徑符號
    safe_filename = os.path.basename(filename)
    return f"正在讀取安全目錄下的檔案: {safe_filename}"

# ==========================================
# 4. 🛡️ 防禦 Brute Force (暴力登入)
# ==========================================
login_attempts = {} 

def check_brute_force(ip_address):
    current_time = time.time()
    
    if ip_address in login_attempts:
        count, last_time = login_attempts[ip_address]
        if count >= 3 and (current_time - last_time < 60):
            return False # 🚫 阻擋
    
    return True # ✅ 放行

def record_failed_login(ip_address):
    if ip_address in login_attempts:
        count, _ = login_attempts[ip_address]
        login_attempts[ip_address] = (count + 1, time.time())
    else:
        login_attempts[ip_address] = (1, time.time())

# ==========================================
# 5. 🛡️ 防禦 Suspicious User-Agent (可疑工具)
# ==========================================
def check_user_agent(user_agent):
    blacklist = ['sqlmap', 'nikto', 'nmap', 'curl']
    ua_lower = user_agent.lower()
    
    for tool in blacklist:
        if tool in ua_lower:
            return False
    return True

# ==========================================
# 6. 🛡️ 防禦 SSRF (伺服器請求偽造)
# ==========================================
def check_ssrf_url(target_url):
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return False
        ip_address = socket.gethostbyname(hostname)
        if ip_address.startswith("127.") or ip_address.startswith("192.168."):
            return False
        return True
    except:
        return False

# ==========================================
# 🧪 自我測試區 (這裡修好了！)
# ==========================================
if __name__ == "__main__":
    print("--- 開始測試 6 大防禦模組 ---\n")

    # 1. 測試 SQLi
    print(f"1. SQLi 防禦測試: {secure_login('admin', 'wrong_pass')}")
    # 這裡把攻擊字串拉出來變數，就不會報錯了
    attack_payload = "' OR '1'='1"
    print(f"   SQLi 攻擊測試: {secure_login('admin', attack_payload)}")

    # 2. 測試 XSS
    print(f"\n2. XSS 防禦結果: {clean_xss_input('<script>alert(1)</script>')}")

    # 3. 測試 Path Traversal
    print(f"\n3. 路徑遍歷防禦: {read_secure_file('../../etc/passwd')}")

    # 4. 測試 暴力登入
    print("\n4. 暴力登入測試 (IP: 10.0.0.1):")
    record_failed_login('10.0.0.1')
    record_failed_login('10.0.0.1')
    record_failed_login('10.0.0.1')
    if check_brute_force('10.0.0.1'):
        print("   -> 允許登入")
    else:python docs/secure_functions.py
    
        print("   -> 🚫 失敗次數過多，IP 已被封鎖！")

    # 5. 測試 User-Agent
    print(f"\n5. 檢查正常瀏覽器: {'通過' if check_user_agent('Mozilla/5.0') else '被擋'}")
    print(f"   檢查駭客工具: {'通過' if check_user_agent('sqlmap/1.0') else '🚫 被擋 (成功)'}")

    # 6. 測試 SSRF
    print(f"\n6. 存取 Google: {'允許' if check_ssrf_url('http://google.com') else '禁止'}")
    print(f"   存取 Localhost: {'允許' if check_ssrf_url('http://127.0.0.1/admin') else '🚫 禁止 (成功)'}")