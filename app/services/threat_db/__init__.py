"""외부 위협 DB 대조 단계 (Stage 2).

GSB(Google Safe Browsing) 실시간 조회와 URLhaus 로컬 스냅샷 조회를 병렬로 수행.
"""

from app.services.threat_db.check import check_threat_db

__all__ = ["check_threat_db"]
