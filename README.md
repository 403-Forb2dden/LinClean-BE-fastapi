# LinClean FastAPI

## 핵심 목표

LinClean FastAPI는 Spring 서비스가 전달한 URL을 열기 전에 분석해 `safe`, `caution`, `danger` verdict와 근거를 반환하는 URL 보안 엔진입니다.

주요 목표는 다음과 같습니다.

- 단축 URL과 리다이렉트를 풀어 실제 도착지를 확인합니다.
- Google Safe Browsing, URLhaus, 도메인 휴리스틱, 콘텐츠 분석, AI 보조 판정을 한 파이프라인에서 합산합니다.
- 사라진 페이지나 400번대 페이지는 무리하게 verdict를 만들지 않고 실패 상태로 Spring에 콜백합니다.
- `caution` 이상 판정에서는 AI 분석 근거와 사용자 행동 가이드를 기존 `ai_reason` 안에 100자 이내로 담습니다.

## 기술 스택

| 구분 | 기술 |
|---|---|
| Language | Python 3.13 |
| API | FastAPI, Pydantic v2 |
| DB | SQLite, SQLAlchemy Async, Alembic |
| HTTP | httpx |
| Scheduler | APScheduler |
| HTML 분석 | BeautifulSoup4, lxml |
| 도메인 분석 | tldextract, RDAP |
| AI | OpenAI Chat Completions, NullAIProvider fallback |
| 테스트 | pytest, pytest-asyncio |
| 품질 도구 | Ruff, mypy |
| 선택 기능 | Playwright 렌더링 분석 |

## 디렉토리 구조

```text
linclean-fastapi/
  app/
    api/                    # FastAPI 라우터, 인증 의존성, 에러 핸들러
    core/                   # 설정, 로깅, 스케줄러, DNS 캐시
    db/                     # SQLAlchemy async engine/session
    middleware/             # request_id, access log
    models/                 # URLhaus 캐시용 ORM 모델
    schemas/                # Pydantic 요청/응답 모델
    services/
      normalizer/           # URL 정규화
      unchainer/            # 리다이렉트 추적
      threat_db/            # GSB, URLhaus 조회
      domain_heuristic/     # 도메인/URL 휴리스틱
      content_analyzer/     # HTML fetch/extract/signals/AI
      pipeline.py           # DB 의존 전체 파이프라인
      db_independent_pipeline.py
      analysis_callback.py  # Spring 콜백
      page_unavailability.py
  alembic/                  # DB migration
  data/                     # SQLite 파일 위치
  reports/                  # 날짜별 평가 결과, 커밋 제외
  scripts/                  # 평가/운영 스크립트, 커밋 제외
  tests/                    # 단위/통합 테스트
```

## 파이프라인 구조

```text
입력 URL
  -> 1. URL 정규화
  -> 2. 리다이렉트 언체이닝
  -> 3. 외부 위협 DB 조회
  -> 4. 도메인/URL 휴리스틱
  -> 5. 콘텐츠 분석
  -> 6. AI 보조 판정
  -> 점수 합산 및 verdict 산출
  -> 동기 응답 또는 Spring 콜백
```

DB 의존 파이프라인은 GSB와 URLhaus를 포함합니다. DB 비의존 파이프라인은 외부 위협 DB 없이 정규화, 언체이닝, 도메인 휴리스틱, 콘텐츠/AI 분석만으로 판정합니다.

## 각 단계별 상세

1. URL 정규화
   입력 URL의 스킴, 호스트, 기본 포트, 경로, 인코딩, fragment를 정리합니다. 스킴이 없는 URL은 HTTPS 우선으로 분석 가능한 형태를 만듭니다.

2. 리다이렉트 언체이닝
   3xx Location 체인을 따라 최종 URL을 찾습니다. 같은 등록 도메인 안의 canonical redirect는 cross-origin으로 보지 않고, 등록 도메인이 달라질 때만 `REDIRECT_CROSS_ORIGIN` 신호를 남깁니다.

3. 외부 위협 DB 조회
   Google Safe Browsing과 URLhaus 로컬 캐시를 조회합니다. 알려진 악성 URL이면 점수와 관계없이 `danger`로 판정할 수 있습니다.

4. 도메인/URL 휴리스틱
   IP 직접 접근, userinfo 포함 URL, 오타 도메인, DGA 유사 도메인, suspicious TLD, open redirect 파라미터, 민감 경로, 무료 호스팅 유도 등을 점수화합니다. 신뢰 도메인은 DGA/typo 오탐을 줄이도록 보정합니다.

5. 콘텐츠 분석
   최종 URL의 HTML을 가져와 title, form, password field, 외부 form action, 민감정보 필드, 기관/브랜드 사칭 문구, 위험 다운로드, meta refresh, 외부 링크 비율을 분석합니다. 404 등 찾을 수 없는 페이지는 `PAGE_UNAVAILABLE` 실패로 조기 종료합니다.

6. AI 보조 판정
   구조화된 페이지 피처와 선행 단계 신호를 OpenAI에 전달합니다. AI 응답은 `phishing`, `suspicious`, `benign` 중 하나이며, `ai_reason`에는 분석 근거와 사용자 행동 가이드를 100자 이내 한 문장으로 담습니다. 예: `브랜드 사칭 정황이 있어 비밀번호나 결제 정보를 입력하지 마세요.`

## 점수 산정 기준

모든 점수는 합산 후 0~100으로 제한합니다. 외부 위협 DB 매치는 고신뢰 신호로 보며, 휴리스틱과 콘텐츠 분석은 보조 신호로 누적합니다.

| 영역 | 신호 | 점수 |
|---|---:|---:|
| 외부 DB | GSB match | 50 |
| 외부 DB | URLhaus match | 50 |
| 도메인 | IP 직접 접근 | 40 |
| 도메인 | URL userinfo | 45 |
| 도메인 | typo domain | 30 |
| 도메인 | punycode IDN | 35 |
| 도메인 | open redirect param | 31 |
| 도메인 | DGA-like | 31 |
| 도메인 | suspicious TLD | 25 |
| 도메인 | new domain | 25 |
| 도메인 | no HTTPS, subdomain/hyphen overuse, hosting platform, sensitive path | 각 20 |
| 도메인 | brand in URL | 30 |
| 도메인 | free hosting lure, URL shortener | 각 25 |
| 콘텐츠 | brand impersonation form | 50 |
| 콘텐츠 | external credential form | 45 |
| 콘텐츠 | sensitive ID field | 30 |
| 콘텐츠 | financial field, external meta refresh | 각 25 |
| 콘텐츠 | PII form, risky download, public agency lure, meta refresh | 각 20 |
| 콘텐츠 | Korean lure text | 15 |
| 콘텐츠 | logo alt impersonation | 10 |
| 콘텐츠 | external link overuse | 5 |
| 콘텐츠 | fetch failed | 15 |
| AI | phishing | 45 |
| AI | suspicious | 31 |

보정 기준:

- 도메인 휴리스틱 점수는 최대 80점입니다.
- 콘텐츠 분석 점수는 최대 100점입니다.
- 종합 점수는 최대 100점입니다.
- 선행 단계 점수가 61점 이상이면 콘텐츠 분석을 건너뛰고 `danger`로 확정할 수 있습니다.
- `not_html`, `too_large`, `unexpected_redirect`, `blocked_host`는 악성 근거가 아니라 분석 불가 성격이 강해 fetch failed 신호만 남기고 점수는 올리지 않습니다.
- 신뢰 도메인에서 AI `suspicious` 단독 판정은 점수를 올리지 않습니다. 단, 외부 form action, 민감정보 필드, 브랜드 사칭 등 강한 신호가 있으면 반영합니다.

## verdict 종류 및 구간별 점수

| Verdict | 점수 구간 | 의미 |
|---|---:|---|
| `safe` | 0~30 | 현재 기준에서 뚜렷한 위험 신호가 낮음 |
| `caution` | 31~60 | 사용자가 링크, 입력 정보, 결제 정보를 한 번 더 확인해야 함 |
| `danger` | 61~100 | 접속, 로그인, 결제, 다운로드를 피해야 하는 위험 상태 |

GSB 또는 URLhaus에 악성으로 등록된 경우에는 점수 구간과 별개로 `danger` verdict가 우선됩니다.

## API 종류및 상세

공통 헤더:

```http
X-Internal-Api-Key: <INTERNAL_API_KEY>
Content-Type: application/json
```

| Method | Path | 설명 |
|---|---|---|
| GET | `/api/v1/health` | 서버 상태 확인 |
| GET | `/api/v1/health/ready` | DB 등 readiness 확인 |
| POST | `/api/v1/analyze` | 비동기 분석 접수. 완료 후 Spring 콜백 전송 |
| POST | `/api/v1/analyze/sync` | GSB, URLhaus 포함 전체 파이프라인 동기 실행 |
| POST | `/api/v1/analyze/db-independent/sync` | 외부 DB 없이 동기 실행 |
| POST | `/api/v1/normalize` | URL 정규화와 리다이렉트 언체이닝 결과 확인 |
| POST | `/api/v1/threat-db` | GSB, URLhaus 조회만 실행 |
| POST | `/api/v1/domain-heuristic` | 도메인/URL 휴리스틱만 실행 |
| POST | `/api/v1/content-analysis` | 콘텐츠 분석과 AI 보조 판정만 실행 |
| POST | `/api/v1/content/fetch-extract` | HTML fetch와 feature 추출만 실행 |

요청 예시:

```json
{
  "url": "https://example.com"
}
```

비동기 분석 접수는 `analysisId`를 함께 보냅니다.

```json
{
  "analysisId": "analysis-1",
  "url": "https://example.com"
}
```

## JSON 응답 예시

동기 분석 성공:

```json
{
  "status": "success",
  "analysis_id": "analysis-1",
  "original_url": "https://example.com",
  "final_url": "https://example.com/",
  "verdict": "caution",
  "score": 31,
  "timings": {
    "total_seconds": 1.23,
    "stages": {
      "normalize": 0.001,
      "unchain": 0.12,
      "threat_db": 0.03,
      "domain_heuristic": 0.2,
      "content_analysis": 0.87
    }
  },
  "stages": {
    "content_analysis": {
      "final_url": "https://example.com/",
      "fetched": true,
      "status_code": 200,
      "score": 31,
      "signals": [],
      "ai_verdict": "suspicious",
      "ai_reason": "로그인 유도 정황이 있어 비밀번호나 결제 정보를 입력하지 마세요.",
      "ai_error": null,
      "ai_model": "gpt-4o-mini"
    }
  }
}
```

찾을 수 없는 페이지:

```json
{
  "status": "failed",
  "analysis_id": "analysis-1",
  "original_url": "https://missing.example",
  "final_url": "https://missing.example",
  "failed_at_stage": "content_analysis",
  "error": "페이지를 찾을 수 없습니다.",
  "error_code": "PAGE_UNAVAILABLE",
  "status_code": 404
}
```

비동기 접수 응답:

```json
{
  "analysisId": "analysis-1",
  "status": "queued"
}
```

Spring 성공 콜백은 camelCase로 전송합니다.

```json
{
  "analysisId": "analysis-1",
  "requestId": "request-1",
  "status": "succeeded",
  "originalUrl": "https://example.com",
  "finalUrl": "https://example.com/",
  "verdict": "caution",
  "score": 31,
  "summary": "로그인 유도 정황이 있어 비밀번호나 결제 정보를 입력하지 마세요.",
  "stages": {
    "contentAnalysis": {
      "fetched": true,
      "hasPasswordField": true,
      "aiVerdict": "suspicious",
      "aiReason": "로그인 유도 정황이 있어 비밀번호나 결제 정보를 입력하지 마세요."
    }
  },
  "engineVersion": "0.1.0",
  "analyzedAt": "2026-05-29T00:00:00Z",
  "elapsedMs": 1234
}
```

로컬 실행:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make run
```

전체 테스트:

```bash
pytest -q
```
