# test_detect.py

from detector import detect_attack

# 1️⃣ SQLi：POST body 裡的 username
req1 = {
    "ip_address": "1.2.3.4",
    "url": "/api/login",
    "http_method": "POST",
    "params": {},
    "body": {
        "username": "' OR 1=1",
        "password": "abc"
    },
    "user_agent": "FakeBrowser"
}

# 2️⃣ SQLi：body 裡 ' OR '1'='1
req2 = {
    "ip_address": "5.6.7.8",
    "url": "/api/login",
    "http_method": "POST",
    "params": {},
    "body": {
        "username": "' OR '1'='1",
        "password": "abc"
    },
    "user_agent": "FakeBrowser"
}

# 3️⃣ SQLi：搜尋欄輸入 union select（POST body）
req3 = {
    "ip_address": "9.9.9.9",
    "url": "/api/search",
    "http_method": "POST",
    "params": {},
    "body": {
        "keyword": "abc UNION SELECT password FROM users"
    },
    "user_agent": "FakeBrowser"
}

# 4️⃣ XSS：keyword 裡有 <script>（POST body）
req4 = {
    "ip_address": "9.9.9.9",
    "url": "/api/search",
    "http_method": "POST",
    "params": {},
    "body": {
        "keyword": "<script>alert(1)</script>"
    },
    "user_agent": "FakeBrowser"
}

# 5️⃣ XSS：GET 參數裡有 <script>（params，順便測 URL decode）
req5 = {
    "ip_address": "10.0.0.1",
    "url": "/search?keyword=%3Cscript%3Ealert(1)%3C/script%3E",
    "http_method": "GET",
    "params": {
        "keyword": "<script>alert(1)</script>"
    },
    "body": {},
    "user_agent": "NormalBrowser"
}

# 6️⃣ 正常查詢（不應該被判成攻擊）
req6 = {
    "ip_address": "10.0.0.2",
    "url": "/api/search",
    "http_method": "POST",
    "params": {},
    "body": {
        "keyword": "我想搜尋安全程式設計"
    },
    "user_agent": "NormalBrowser"
}

# 7️⃣ 暴力登入：同一 IP 在短時間內連續多次 /api/login
brute_force_requests = []
for i in range(6):  # 連續 6 次
    brute_force_requests.append({
        "ip_address": "123.45.67.89",
        "url": "/api/login",
        "http_method": "POST",
        "params": {},
        "body": {
            "username": f"user{i}",
            "password": "wrong-password"
        },
        "user_agent": "BruteForceScript"
    })

# 8️⃣ Path Traversal：嘗試讀 /etc/passwd（正常寫法）
req_pt1 = {
    "ip_address": "8.8.8.8",
    "url": "/download?file=../../etc/passwd",
    "http_method": "GET",
    "params": {
        "file": "../../etc/passwd"
    },
    "body": {},
    "user_agent": "HackerBrowser"
}

# 9️⃣ Path Traversal：Windows 路徑（用 raw string 保留反斜線）
req_pt2 = {
    "ip_address": "8.8.4.4",
    "url": "/download",
    "http_method": "POST",
    "params": {},
    "body": {
        "path": r"..\..\Windows\system32\config\sam"
    },
    "user_agent": "HackerBrowser"
}

# 🔟 Path Traversal（URL 編碼版）：測試 unquote 是否有作用
req_pt3 = {
    "ip_address": "1.1.1.1",
    "url": "/download?file=..%2f..%2fetc%2fpasswd",
    "http_method": "GET",
    "params": {
        "file": "..%2f..%2fetc%2fpasswd"
    },
    "body": {},
    "user_agent": "EncodedHacker"
}

# 1️⃣1️⃣ 可疑 User-Agent：沒有明顯 payload，但 UA 看起來像工具
req_ua = {
    "ip_address": "2.2.2.2",
    "url": "/",
    "http_method": "GET",
    "params": {},
    "body": {},
    "user_agent": "sqlmap/1.6.0#stable (http://sqlmap.org)"
}

# 1️⃣2️⃣ Command Injection：body 裡出現 shell 指令
req_cmd = {
    "ip_address": "3.3.3.3",
    "url": "/api/ping",
    "http_method": "POST",
    "params": {},
    "body": {
        # 同時含有 ";" 和 "rm -rf /" → 一定會被偵測
        "host": "8.8.8.8; rm -rf /"
    },
    "user_agent": "HackerScript"
}

# 1️⃣3️⃣ SSRF：嘗試要求內網 / localhost
req_ssrf1 = {
    "ip_address": "4.4.4.4",
    "url": "/api/fetch",
    "http_method": "POST",
    "params": {},
    "body": {
        "target_url": "http://127.0.0.1:8080/admin"
    },
    "user_agent": "SSRFTester"
}

# 1️⃣4️⃣ 正常對外 URL（不應該被當成 SSRF）
req_ssrf2 = {
    "ip_address": "4.4.4.5",
    "url": "/api/fetch",
    "http_method": "POST",
    "params": {},
    "body": {
        "target_url": "https://example.com/image.png"
    },
    "user_agent": "NormalBrowser"
}


print("case1  (SQLi body 1):", detect_attack(req1))
print("case2  (SQLi body 2):", detect_attack(req2))
print("case3  (SQLi body 3):", detect_attack(req3))
print("case4  (XSS body):   ", detect_attack(req4))
print("case5  (XSS params): ", detect_attack(req5))
print("case6  (normal):     ", detect_attack(req6))

for idx, r in enumerate(brute_force_requests, start=1):
    result = detect_attack(r)
    print(f"brute_force try #{idx}:", result)

print("case8  (Path Traversal 1):           ", detect_attack(req_pt1))
print("case9  (Path Traversal 2):           ", detect_attack(req_pt2))
print("case10 (Path Traversal 3 - encoded):", detect_attack(req_pt3))
print("case11 (Suspicious UA):              ", detect_attack(req_ua))
print("case12 (Command Injection):          ", detect_attack(req_cmd))
print("case13 (SSRF - internal target):     ", detect_attack(req_ssrf1))
print("case14 (SSRF - normal external):     ", detect_attack(req_ssrf2))
