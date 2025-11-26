以 WebGoat 攻擊實驗概念為基礎，重新實作一個「可攻擊的小型網站」與「攻擊偵測＋監控平台」，用於展示 SQL Injection、XSS、暴力登入等攻擊行為的觸發方式、紀錄方式與防禦思路。

---

## 專題目標

1. 實作一個**有漏洞的測試網站（Vulnerable Site）**
2. 撰寫**攻擊偵測模組（Detection）**
3. 將攻擊事件記錄進 **Logging system / DB**
4. 製作一個**可視化後台 Dashboard** 顯示所有攻擊行為
5. 最後示範**安全修補版本（Prevention）**

---

## 系統架構總覽

```plaintext
   [User / Attacker]
            │
            ▼
   ┌───────────────────┐
   │   Vulnerable Site │  ← 組員 A
   │ (login/search/etc.) 
   └───────────────────┘
            │ 送出的 Request
            ▼
   ┌───────────────────┐
   │  Detection Module │  ← 組員 B
   │  detect_attack()  │
   └───────────────────┘
            │ 若為攻擊 → 生成 AttackEvent
            ▼
   ┌───────────────────┐
   │   Logging Module  │  ← 組員 C
   │ log_attack()      │
   └───────────────────┘
            │ 儲存資料
            ▼
   ┌───────────────────┐
   │ Admin Dashboard   │  ← 組員 D
   │ 監控頁面 / 圖表化   │
   └───────────────────┘

   （docs / 防禦版） ← 組員 E
````

---

## 專案資料夾說明

```
/vuln-site     → A：脆弱網站（故意有 SQLi、XSS、越權漏洞）
/detection     → B：攻擊偵測函式 detect_attack()
/logging       → C：紀錄 AttackEvent + 提供 /api/attacks
/dashboard     → D：監控後台 /admin/monitor
/docs          → E：文件、防禦、簡報草稿
```

---

## 五人分工

| 組員 | 負責項目                                       |
| -- | ------------------------------------------ |
| 蔡秉凱  | Vulnerable Site（login / search / admin）    |
| 林秀萍  | Detection Module（SQLi / XSS / brute-force） |
| 張峻碩  | Logging Module（log_attack + API）           |
| 施淯馨  | Admin Dashboard（圖表 / 表格）                   |
| 王詳博  | 文件撰寫、防禦版本、架構圖                              |

---

## 必要 API（標準化）

| 路徑             | 方法   | 說明                            |
| -------------- | ---- | ----------------------------- |
| `/api/login`   | POST | 登入（有漏洞）                       |
| `/api/search`  | POST | 搜尋 / 留言（有漏洞）                  |
| `/api/attacks` | GET  | 取得所有 AttackEvent（Dashboard 用） |

---

## 專案啟動方式

### 1. Clone

```bash
git clone https://github.com/xin-kz910/web-attack-monitoring.git
cd web-attack-monitoring
```

### 2. 每次寫程式前先更新

```bash
git pull
```

### 3. 寫完上傳

```bash
git add 自己的資料夾/
git commit -m "describe what you did"
git push
```
