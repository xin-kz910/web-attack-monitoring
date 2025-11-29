# 🛡️ 網站攻擊防禦機制說明 (Defense Mechanisms)

本文檔說明本專案針對六大常見漏洞的防禦實作方式與原理技術。

---

## 1. SQL Injection (SQLi) 防禦

針對 `POST /api/login` 登入功能，將「字串拼接」改為「參數化查詢」。

* **API 路徑：** `POST /api/login`
* **輸入欄位：** `username`, `password`

### ❌ 不安全寫法 (Vulnerable)
```python
# 危險！直接把字串拼起來，駭客輸入 ' OR '1'='1 就能登入
sql = f"SELECT * FROM users WHERE username = '{data['username']}' AND password = '{data['password']}'"
cursor.execute(sql)# 🛡️ 登入系統防禦實作 (SQL Injection Defense)

針對本專案 `POST /api/login` 接口，我們使用 **Prepared Statement (參數化查詢)** 來修補 SQL Injection 漏洞。

## 📋 規格說明 (Spec)
* **API 路徑**：`POST /api/login`
* **HTTP Method**：`POST`
* **Request Body**：
  ```json
  {
    "username": "...",
    "password": "..."
  }