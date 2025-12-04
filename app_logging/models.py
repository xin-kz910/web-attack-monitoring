from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Text
from .db import Base


class AttackLog(Base):
    """
    對應 MySQL 中的 attack_logs 資料表：

    id          INT (PK, AUTO_INCREMENT)
    timestamp   DATETIME
    ip_address  VARCHAR
    url         VARCHAR
    payload     TEXT
    attack_type VARCHAR
    user_agent  TEXT
    """
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=False)
    url = Column(String(2048), nullable=False)
    payload = Column(Text)
    attack_type = Column(String(50), nullable=False)
    severity = Column(String(20), default="MEDIUM")
    user_agent = Column(Text)
