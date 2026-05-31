FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # app 이 site-packages 에 설치돼 alembic/uvicorn 이 그쪽을 import 하므로
    # SQLite 경로를 절대경로로 고정 (PROJECT_ROOT 추론이 site-packages 를 가리켜
    # 쓰기 불가 위치에 DB 디렉토리를 만들려다 실패하는 문제 방지).
    SQLITE_PATH=/app/data/linclean.db \
    TLDEXTRACT_CACHE=/tmp/tldextract

WORKDIR /app

# hatchling 이 app 패키지를 빌드해야 하므로 install 전에 소스 복사
COPY pyproject.toml ./
COPY app ./app
RUN pip install .

# 마이그레이션 + 기동 스크립트
COPY alembic.ini ./
COPY alembic ./alembic
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# non-root + 데이터 디렉토리(SQLite) 소유권
RUN useradd -m -u 1000 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').status==200 else 1)"

ENTRYPOINT ["./entrypoint.sh"]
