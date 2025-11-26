# detector.py

"""
DetectionInput 格式：
{
  "ip_address": "string",
  "url": "string",
  "http_method": "string",
  "params": dict,
  "body": dict,
  "user_agent": "string"
}

DetectionResult 格式：
{
  "is_attack": bool,
  "attack_type": "SQLI" | "XSS" | "BRUTE_FORCE" | "PATH_TRAVERSAL"
                 | "CMD_INJECTION" | "SSRF" | "SUSPICIOUS_UA" | "NONE",
  "severity": "LOW" | "MEDIUM" | "HIGH",
  "payload": "string",
  "should_block": bool   # 是否建議阻擋這個請求
}
"""

import time
import json
import os
from typing import Dict, List, Tuple
from urllib.parse import unquote, urlparse  # 用來解碼 URL / 參數 & 解析 URL
from datetime import datetime, timezone, timedelta

# =====================================================
# 1. 預設攻擊關鍵字規則（如果沒有 rules.json 就用這些）
# =====================================================

DEFAULT_RULES = {
    "SQLI_PATTERNS": [
        # 基本 or 1=1 類型
        " or 1=1",
        "' or '1'='1",
        "\" or \"1\"=\"1",
        " or '1'='1",
        " or 1=1 --",
        " or 1=1--",
        " or 1=1#",
        " or 1=1/*",
        " union select",
        "--",       # SQL 註解
        ";--",
        "/*",
        "*/",
        # time-based / function 類型 SQLi
        "sleep(",
        "benchmark(",
        "pg_sleep(",
        "waitfor delay",
    ],
    "XSS_PATTERNS": [
        "<script",      # <script>...</script>
        "onerror=",     # <img src=x onerror=...>
        "onload=",      # onload 事件
        "javascript:",  # href="javascript:alert(1)"
        "alert(",       # alert(1)
        # 更多常見事件 handler
        "onclick=",
        "onmouseover=",
        "onmouseenter=",
        "onfocus=",
        "onblur=",
        "onchange=",
        "onsubmit=",
    ],
    "PATH_TRAVERSAL_PATTERNS": [
        "../",
        "..\\",
        "..%2f",        # URL 編碼的 ../（保留，雖然我們也會先解碼）
        "%2e%2e%2f",    # ../ 的另一種編碼
        "/etc/passwd",
        "/etc/shadow",
        "c:\\windows",
        "c:/windows",
        "windows\\system32",
    ],
    # 可疑 User-Agent 關鍵字
    "SUSPICIOUS_UA_PATTERNS": [
        "sqlmap",
        "python-requests",
        "curl",
        "scanner",
        "nmap",
        "acunetix",
        "burp",
        "fuzzer",
    ],
    # NEW：Command Injection 關鍵字（簡化版）
    "COMMAND_INJECTION_PATTERNS": [
        # 管線與指令連接符號（示範用，實務會更嚴謹）
        ";",
        "&&",
        "||",
        "|",
        "`",
        "$(",
        # 常見惡意指令片段
        "bash -c",
        "sh -c",
        "cmd /c",
        "powershell",
        "nc ",
        "netcat",
        "wget ",
        "curl ",
        " cat /etc/passwd",
        " rm -rf /",
    ],
}

# 暴力登入偵測設定：同一 IP 在 60 秒內超過 5 次 login 嘗試
BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_THRESHOLD = 5

# 紀錄每個 IP 的登入嘗試時間戳
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}

# 這裡會放真正使用的規則（可能來自 DEFAULT，也可能被 rules.json 覆蓋）
RULES = DEFAULT_RULES.copy()

# 預設模式：只記錄不阻擋
MODE = "LOG_ONLY"   # 可由 rules.json 改成 "BLOCK"


# =====================================================
# 2. 載入外部規則檔（rules.json，如果有的話）
# =====================================================

def _load_rules_from_file(filename: str = "rules.json") -> None:
    """
    嘗試從 rules.json 載入規則與模式。
    如果檔案不存在或格式錯誤，就使用 DEFAULT_RULES + 預設 MODE。
    """
    global RULES, MODE, BRUTE_FORCE_WINDOW_SECONDS, BRUTE_FORCE_THRESHOLD

    if not os.path.exists(filename):
        # 找不到檔案就維持預設規則與模式
        return

    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 只更新我們認得的 key，避免亂掉
        for key in DEFAULT_RULES.keys():
            if key in data and isinstance(data[key], list):
                RULES[key] = data[key]

        # 從 JSON 調整 MODE（允許 LOG_ONLY 或 BLOCK）
        mode = data.get("MODE")
        if isinstance(mode, str) and mode.upper() in ("LOG_ONLY", "BLOCK"):
            MODE = mode.upper()

        # （選擇性）也可以讓 JSON 調整暴力登入參數
        if isinstance(data.get("BRUTE_FORCE_WINDOW_SECONDS"), int):
            BRUTE_FORCE_WINDOW_SECONDS = int(data["BRUTE_FORCE_WINDOW_SECONDS"])
        if isinstance(data.get("BRUTE_FORCE_THRESHOLD"), int):
            BRUTE_FORCE_THRESHOLD = int(data["BRUTE_FORCE_THRESHOLD"])

    except Exception:
        # 有問題就直接忽略，維持預設
        RULES = DEFAULT_RULES.copy()
        MODE = "LOG_ONLY"


# 啟動時就先試著載入一次
_load_rules_from_file()


# =====================================================
# 3. 小工具函式
# =====================================================

def _to_str(value) -> str:
    """保險一點，把各種型別轉成字串。"""
    return str(value) if value is not None else ""

def _now_tw() -> str:
    """
    回傳台灣時間（UTC+8）的字串，24 小時制。
    例如：2025-11-26 22:45:12 +0800
    """
    tz = timezone(timedelta(hours=8))  # 台灣時區 = UTC+8
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S %z")


def _collect_fields(input_data: dict) -> Dict[str, str]:
    """
    把 url / params / body / user_agent 全部攤平成一個 dict：
    {
      "url": "...",
      "param.username": "...",
      "body.password": "...",
      "user_agent": "...",
      ...
    }
    之後就可以一個一個欄位去檢查。

    會先對 URL、params、body 做 URL decode（unquote），
    讓 %3Cscript%3E 這類編碼過的 payload 也能被偵測到。
    """
    pieces: Dict[str, str] = {}

    # URL、方法、User-Agent
    raw_url = _to_str(input_data.get("url", ""))
    decoded_url = unquote(raw_url)  # URL 解碼
    pieces["url"] = decoded_url

    pieces["http_method"] = _to_str(input_data.get("http_method", ""))
    pieces["user_agent"] = _to_str(input_data.get("user_agent", ""))

    # params 可能是 GET query string 的參數
    params = input_data.get("params", {}) or {}
    for k, v in params.items():
        raw = _to_str(v)
        decoded = unquote(raw)      # 參數也先解碼一次
        pieces[f"param.{k}"] = decoded

    # body 是 POST/PUT 的內容
    body = input_data.get("body", {}) or {}
    for k, v in body.items():
        raw = _to_str(v)
        decoded = unquote(raw)      # body 內容也先解碼
        pieces[f"body.{k}"] = decoded

    return pieces


def _find_pattern(pieces: Dict[str, str], patterns: List[str]) -> Tuple[bool, str, str]:
    """
    在所有欄位裡面找有沒有出現任一 pattern。
    回傳：
      (是否命中, 該欄位名稱, 該欄位原始內容)
    沒找到則回傳 (False, "", "")。
    """
    for field_name, raw_value in pieces.items():
        value_lower = raw_value.lower()
        for p in patterns:
            if p and p.lower() in value_lower:
                return True, field_name, raw_value
    return False, "", ""


def _check_bruteforce(input_data: dict) -> Tuple[bool, str]:
    """
    暴力登入偵測：
    - 只看 URL 中有 "login" 的請求（當作登入嘗試）
    - 以 ip_address 當 key，記錄最近一段時間的嘗試
    - 同一 IP 在 BRUTE_FORCE_WINDOW_SECONDS 內超過 BRUTE_FORCE_THRESHOLD 次，就算 BRUTE_FORCE
    """
    ip = _to_str(input_data.get("ip_address", ""))
    url = _to_str(input_data.get("url", "")).lower()
    method = _to_str(input_data.get("http_method", "")).upper()

    # 不是 login 相關的就不算登入嘗試
    if "login" not in url:
        return False, ""

    # 只統計 POST /login（可以視情況調整）
    if method != "POST":
        return False, ""

    now = time.time()
    attempts = _LOGIN_ATTEMPTS.get(ip, [])
    attempts.append(now)

    # 移除超過時間窗的舊紀錄
    cutoff = now - BRUTE_FORCE_WINDOW_SECONDS
    attempts = [t for t in attempts if t >= cutoff]
    _LOGIN_ATTEMPTS[ip] = attempts

    if len(attempts) >= BRUTE_FORCE_THRESHOLD:
        info = f"{ip} tried login {len(attempts)} times in {BRUTE_FORCE_WINDOW_SECONDS} seconds"
        return True, info

    return False, ""


def _check_suspicious_ua(input_data: dict) -> Tuple[bool, str]:
    """
    檢查 User-Agent 是否包含常見掃描器 / 攻擊工具字樣。
    命中時視為 SUSPICIOUS_UA，屬於低～中風險（輕量級告警）。
    """
    ua = _to_str(input_data.get("user_agent", "")).lower()
    if not ua:
        return False, ""

    for pattern in RULES.get("SUSPICIOUS_UA_PATTERNS", []):
        p = pattern.lower()
        if p and p in ua:
            return True, ua
    return False, ""


def _is_private_or_metadata_ip(host: str) -> bool:
    """
    SSRF 用：簡單判斷 host 是否看起來像內網或 metadata 服務。
    不是要百分之百正確，只是 demo 用。
    """
    host = host.lower()

    # 一些常見敏感 host
    if host in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
        return True

    parts = host.split(".")
    if len(parts) < 4 or not all(p.isdigit() for p in parts[:4]):
        return False

    a, b, c, d = [int(p) for p in parts[:4]]

    # 10.0.0.0/8
    if a == 10:
        return True
    # 192.168.0.0/16
    if a == 192 and b == 168:
        return True
    # 172.16.0.0 ~ 172.31.0.0
    if a == 172 and 16 <= b <= 31:
        return True
    # 169.254.x.x（常見 metadata / link-local）
    if a == 169 and b == 254:
        return True

    return False


def _check_ssrf(input_data: dict) -> Tuple[bool, str]:
    """
    NEW：簡化版 SSRF 偵測。
    想像有一個 API 會讓 user 填 URL（例如 /api/fetch?url=...），
    這裡會找出所有看起來像 URL 的欄位，判斷是否打到內網 / metadata。
    """
    candidates: List[str] = []

    # 先把原始 URL 也算進可能的 payload
    raw_url = unquote(_to_str(input_data.get("url", "")))
    candidates.append(raw_url)

    # params / body 裡的內容
    params = input_data.get("params", {}) or {}
    body = input_data.get("body", {}) or {}

    for d in (params, body):
        for _, v in d.items():
            s = unquote(_to_str(v))
            candidates.append(s)

    for value in candidates:
        v = value.strip()
        if not v:
            continue

        # 找出看起來像 http/https 的 URL
        lower = v.lower()
        url_str = None
        if lower.startswith("http://") or lower.startswith("https://"):
            url_str = v
        else:
            idx = lower.find("http://")
            if idx == -1:
                idx = lower.find("https://")
            if idx != -1:
                url_str = v[idx:]

        if not url_str:
            continue

        try:
            parsed = urlparse(url_str)
        except Exception:
            continue

        host = parsed.hostname
        if not host:
            continue

        if _is_private_or_metadata_ip(host):
            # 命中 SSRF 風險
            return True, url_str

    return False, ""


def _apply_block_flag(result: dict) -> dict:
    """
    根據全域 MODE，決定這次偵測結果是否應該被阻擋。
    - LOG_ONLY：永遠不阻擋（should_block = False）
    - BLOCK：只要 is_attack = True 就 should_block = True
    """
    if result.get("is_attack") and MODE == "BLOCK":
        result["should_block"] = True
    else:
        result["should_block"] = False
    return result


# =====================================================
# 4. 主偵測函式
# =====================================================

def detect_attack(input_data: dict) -> dict:
    """
    核心偵測函式。

    會檢查：
    - SQL Injection：RULES["SQLI_PATTERNS"]
    - XSS：RULES["XSS_PATTERNS"]
    - Path Traversal：RULES["PATH_TRAVERSAL_PATTERNS"]
    - Command Injection：RULES["COMMAND_INJECTION_PATTERNS"]
    - Brute Force Login
    - SSRF（打內網 / metadata IP）
    - Suspicious User-Agent：RULES["SUSPICIOUS_UA_PATTERNS"]
    """
    # 預設結果（沒有攻擊）
    result = {
        "is_attack": False,
        "attack_type": "NONE",
        "severity": "LOW",
        "payload": "",
        "should_block": False,   # 先預設 False，最後再由 _apply_block_flag 決定
    
        "ip_address": _to_str(input_data.get("ip_address", "")),
        "timestamp": _now_tw(),
    }

    # 把所有欄位收集起來（url / params / body / user_agent）
    pieces = _collect_fields(input_data)

    # 檢查 SQL Injection
    hit, field, value = _find_pattern(pieces, RULES["SQLI_PATTERNS"])
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "SQLI"
        result["severity"] = "HIGH"
        result["payload"] = f"{field}: {value}"
        return _apply_block_flag(result)

    # 檢查 XSS
    hit, field, value = _find_pattern(pieces, RULES["XSS_PATTERNS"])
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "XSS"
        result["severity"] = "MEDIUM"
        result["payload"] = f"{field}: {value}"
        return _apply_block_flag(result)

    # 檢查 Path Traversal（目錄遍歷 / 檔案讀取）
    hit, field, value = _find_pattern(pieces, RULES["PATH_TRAVERSAL_PATTERNS"])
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "PATH_TRAVERSAL"
        result["severity"] = "HIGH"
        result["payload"] = f"{field}: {value}"
        return _apply_block_flag(result)

    # 檢查 Command Injection
    hit, field, value = _find_pattern(pieces, RULES["COMMAND_INJECTION_PATTERNS"])
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "CMD_INJECTION"
        result["severity"] = "CRITICAL"  # 你也可以在報告特別強調
        result["payload"] = f"{field}: {value}"
        return _apply_block_flag(result)

    # 檢查暴力登入（Brute Force）
    hit, info = _check_bruteforce(input_data)
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "BRUTE_FORCE"
        result["severity"] = "MEDIUM"
        result["payload"] = info
        return _apply_block_flag(result)

    # 檢查 SSRF
    hit, url_str = _check_ssrf(input_data)
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "SSRF"
        result["severity"] = "HIGH"
        result["payload"] = f"target_url: {url_str}"
        return _apply_block_flag(result)

    # 檢查可疑 User-Agent
    hit, ua = _check_suspicious_ua(input_data)
    if hit:
        result["is_attack"] = True
        result["attack_type"] = "SUSPICIOUS_UA"
        result["severity"] = "LOW"
        result["payload"] = f"user_agent: {ua}"
        return _apply_block_flag(result)

    # 沒有任何攻擊
    return _apply_block_flag(result)
