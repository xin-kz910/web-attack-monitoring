from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
import random # 記得加入這個，為了產生測試資料

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
    severity: str
    user_agent: Optional[str] = None

    class Config:
        orm_mode = True


# ========== Router 本體 ==========

router = APIRouter(
    prefix="/api",
    tags=["logging"],
)


@router.get("/logs", response_model=List[AttackLogOut])
def list_attack_logs(limit: int = 100, db: Session = Depends(get_db)):
    """
    對應前端 fetch("/api/logs")
    """
    logs = get_attack_logs(db, limit=limit)
    return logs


@router.post("/test-attack", response_model=AttackLogOut)
async def test_attack(request: Request, db: Session = Depends(get_db)):
    """
    產生測試資料用
    """
    # 隨機產生一些 severity 和 type 讓圖表好看一點
    types = ["SQLI", "XSS", "BRUTE_FORCE", "PATH_TRAVERSAL"]
    severities = ["HIGH", "MEDIUM", "LOW"]
    
    log = save_attack_log(
        db=db,
        ip_address=request.client.host,
        url=str(request.url),
        payload=f"' OR 1=1 -- {random.randint(1, 999)}",
        attack_type=random.choice(types),
        severity=random.choice(severities),
        user_agent=request.headers.get("user-agent"),
    )
    return log