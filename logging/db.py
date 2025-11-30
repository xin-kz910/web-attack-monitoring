from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ===== 請改成你們自己的 MySQL 設定 =====
MYSQL_USER = "your_user"        # 例如 "root"
MYSQL_PASSWORD = "your_password"
MYSQL_HOST = "127.0.0.1"        # 或資料庫主機 IP
MYSQL_PORT = 3306
MYSQL_DB = "security_demo"      # 你們建 attack_logs 那個 DB 名稱
# ====================================

SQLALCHEMY_DATABASE_URL = (
    f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}"
    f"@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}?charset=utf8mb4"
)

# 建立 Engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,       # 斷線自動偵測
)

# 建立 Session 工廠
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base 給 models 繼承
Base = declarative_base()
