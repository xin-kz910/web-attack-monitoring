# reset_db.py
from app_logging.db import engine, Base
from app_logging.models import AttackLog  # 確保模型被載入

print("正在重置資料庫...")

# 1. 刪除所有資料表 (Drop Tables)
# 這會把 attack_logs 表從 MySQL 中刪除
Base.metadata.drop_all(bind=engine)
print("✅ 舊資料表已刪除")

# 2. 重新建立資料表 (Create Tables)
# 這次建立的就會包含 severity 欄位了
Base.metadata.create_all(bind=engine)
print("✅ 新資料表已建立 (包含 severity 欄位)")

print("重置完成！請重新執行 main.py")