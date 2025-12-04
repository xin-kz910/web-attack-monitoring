import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

# 1. 引用你的後端模組
# 注意：你的資料夾名稱現在是 app_logging，所以這裡要用 app_logging
from app_logging.db import engine, Base
from app_logging.router import router as logging_router

# 2. 初始化資料庫
# 這行會檢查資料庫連線，並自動建立 attack_logs 資料表 (如果不存在的話)
Base.metadata.create_all(bind=engine)

app = FastAPI()

# 3. 掛載 API 路由
# 這樣前端才能透過 /api/logs 拿到資料
app.include_router(logging_router)

# 4. 設定 Dashboard 頁面路由
@app.get("/admin/monitor", response_class=HTMLResponse)
async def read_dashboard():
    # 取得 main.py 目前所在的資料夾路徑 (絕對路徑)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 組合路徑：指向 dashboard 資料夾內的 admin-monitor.html
    # 對應你的截圖結構： root/dashboard/admin-monitor.html
    file_path = os.path.join(base_dir, "dashboard", "admin-monitor.html")
    
    # 除錯檢查：如果檔案找不到，會在網頁上直接顯示路徑錯誤資訊
    if not os.path.exists(file_path):
        return f"""
        <h1>系統錯誤：找不到 HTML 檔案</h1>
        <p>系統試圖讀取的位置是：<br><b>{file_path}</b></p>
        <p>請確認你的 admin-monitor.html 確實放在 dashboard 資料夾內。</p>
        """

    # 讀取檔案內容並回傳
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

# 5. 啟動伺服器
if __name__ == "__main__":
    print("---------------------------------------------------------")
    print("🚀 Mini WAF 監控系統啟動中...")
    print("👉 請開啟瀏覽器訪問: http://127.0.0.1:8000/admin/monitor")
    print("---------------------------------------------------------")
    
    # 啟動 uvicorn 伺服器
    uvicorn.run(app, host="127.0.0.1", port=8000)