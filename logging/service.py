from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from .models import AttackLog


def save_attack_log(
    db: Session,
    ip_address: str,
    url: str,
    payload: Optional[str],
    attack_type: str,
    user_agent: Optional[str] = None,
) -> AttackLog:
    """
    給「攻擊偵測模組」呼叫，把一筆攻擊紀錄寫進 attack_logs。
    """
    log = AttackLog(
        timestamp=datetime.utcnow(),
        ip_address=ip_address,
        url=url,
        payload=payload,
        attack_type=attack_type,
        user_agent=user_agent,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_attack_logs(db: Session, limit: int = 100) -> List[AttackLog]:
    """
    給 Dashboard / 其他地方用，讀出最近 N 筆攻擊紀錄。
    """
    return (
        db.query(AttackLog)
        .order_by(AttackLog.timestamp.desc())
        .limit(limit)
        .all()
    )
