# 🏗️ 系統架構說明 (Architecture)

本專案模擬一個完整的 Web 攻防演練環境。

## 系統流程圖
```text
[攻擊者/使用者] 
      ⬇️ (發送 Request)
[攻擊偵測模組 (Detection)] 
      ⬇️ (判斷是否惡意)
      ┣━━ 🚨 是攻擊 ━━━➡ [紀錄模組 (Logging)] ━━➡ [資料庫 (Logs)]
      ⬇️ (正常請求)
[網站主機 (Vuln Site)] 
      ⬇️ (存取資料)
[使用者資料庫 (Users DB)]