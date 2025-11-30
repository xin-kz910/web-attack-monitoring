from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .db import SessionLocal
from .service import get_attack_logs, save_attack_log


# ========== DB 依賴注入 ==========

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ========== Pydantic 輸出模型 ==========

class AttackLogOut(BaseModel):
    id: int
    timestamp: datetime
    ip_address: str
    url: str
    payload: Optional[str] = None
    attack_type: str
    user_agent: Optional[str] = None

    class Config:
        orm_mode = True


# ========== Router 本體 ==========

router = APIRouter(
    prefix="/logging",
    tags=["logging"],
)


@router.get("/attack-logs", response_model=List[AttackLogOut])
def list_attack_logs(limit: int = 100, db: Session = Depends(get_db)):
    """
    例：GET /logging/attack-logs?limit=50
    回傳最近 limit 筆攻擊紀錄。
    """
    logs = get_attack_logs(db, limit=limit)
    return logs


@router.post("/test-attack", response_model=AttackLogOut)
async def test_attack(request: Request, db: Session = Depends(get_db)):
    """
    自我測試用：
    呼叫這支 API 會寫一筆假攻擊紀錄到 attack_logs。
    之後正式上線可以關掉或限內網使用。
    """
    log = save_attack_log(
        db=db,
        ip_address=request.client.host,
        url=str(request.url),
        payload="' OR 1=1 --",          # 假裝一個 SQLi payload
        attack_type="SQLi",
        user_agent=request.headers.get("user-agent"),
    )
    return log
