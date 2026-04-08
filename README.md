# LinClean-BE-fastapi (URL 보안 엔진)

**LinClean의 URL 검역 백엔드입니다.** <br>
카톡·문자·메일로 받은 링크를 열기 전에 4단계 파이프라인으로 검사해
**안전 / 주의 / 위험** 판정과 그 근거를 산출하는 **상태 비저장(stateless) 분석 전용 서버** 입니다.

---

## 기술 스택

| 분류 | 기술                                              | 비고 |
|------|-------------------------------------------------|------|
| Framework | **FastAPI**                                     | lifespan, async, app factory |
| Language | **Python 3.11+**                                | 타입 힌트, async/await |
| 로컬 캐시 DB | **SQLite + aiosqlite**                          | URLhaus 등 외부 피드 캐시 전용 |
| ORM | **SQLAlchemy 2.0 (async)**                      | DeclarativeBase + naming convention |
| Migration | **Alembic**                                     | SQLite batch mode |
| HTTP Client | **httpx**                                       | 외부 API 호출 (GSB / RDAP / Claude / Spring 콜백) |
| Crawler | **BeautifulSoup4 + requests**                   | 페이지 본문 추출, 피싱 신호 탐지 |
| Domain Lookup | **RDAP (httpx)**                                | 도메인 등록일·만료일·레지스트라 조회 |
| Async Queue | **Celery + Redis**                              | 무거운 분석 작업 큐잉, TTL 캐시 |
| Scheduler | **APScheduler**                                 | URLhaus 주기 동기화, 링크 생존 모니터링 |
| Validation | **Pydantic v2 + pydantic-settings**             | 요청·응답·환경변수 |
| Logging | **structlog**                                   | 구조적 로깅 + request_id 자동 바인딩 |
| Lint / Format | **Ruff**                                        | E/F/I/B/SIM/S/UP 룰셋 |
| Type Check | **mypy (strict)**                               | pydantic 플러그인 |
| Test | **pytest + pytest-asyncio + httpx AsyncClient** | ASGI 테스트 |
| Packaging | **hatchling**                                   | PEP 621 |
| AI | **모델 미정**                                       | 페이지 콘텐츠 정적 분석 보조 |

---

## 디렉토리 구조

```
linclean-fastapi/
├── app/
│   ├── main.py                       # FastAPI 앱 팩토리 + lifespan
│   │
│   ├── api/                          # HTTP 계층
│   │   ├── deps.py                   # 공용 의존성 (DBSession 등)
│   │   ├── error_handlers.py         # 글로벌 예외 → ErrorResponse 변환
│   │   └── v1/
│   │       ├── router.py             # v1 라우터 집합
│   │       └── endpoints/
│   │           └── health.py         # /health, /health/ready
│   │
│   ├── core/                         # 인프라/공통
│   │   ├── config.py                 # 환경변수 (pydantic-settings)
│   │   ├── logging.py                # structlog + stdlib bridge
│   │   └── exceptions.py             # AppError 도메인 예외 계층
│   │
│   ├── db/                           # 영속성 계층 (외부 피드 캐시 전용)
│   │   ├── base.py                   # DeclarativeBase + naming convention
│   │   └── session.py                # async engine, get_db, SQLite PRAGMA
│   │
│   ├── middleware/
│   │   └── request_context.py        # X-Request-ID + 구조적 access log
│   │
│   ├── models/                       # SQLAlchemy ORM 모델 (외부 피드 캐시)
│   │   └── __init__.py               # Alembic autogen 용 import 모음
│   │
│   ├── schemas/                      # Pydantic DTO
│   │   └── common.py                 # HealthResponse, ErrorResponse 등
│   │
│   └── services/                     # 도메인/비즈니스 로직
│       (4단계 파이프라인 / 외부 연동 / Spring 콜백이 들어갈 자리)
│
├── alembic/                          # 외부 피드 캐시 스키마 마이그레이션
│   ├── env.py                        # SQLite + batch mode 설정
│   ├── script.py.mako
│   └── versions/
│
├── tests/                            # pytest 테스트
│   ├── conftest.py                   # ASGI AsyncClient + 인메모리 SQLite
│   └── test_health.py
│
├── docs/                             # 기획서 등 설계 문서
│   └── LinClean_기능_초안.pdf
│
├── data/                             # SQLite 캐시 파일 (gitignore)
│
├── alembic.ini
├── pyproject.toml                    # 의존성 + ruff/mypy/pytest 설정
├── Makefile                          # install / run / test / migrate ...
├── .pre-commit-config.yaml
├── .env.example
└── README.md
```

### 계층별 책임

- **`api/`** — HTTP 입출력만 담당. 라우터는 얇게 유지하고, 비즈니스 로직은
  `services/` 에 위임합니다. 의존성(`Depends`)은 `api/deps.py` 에 모아둡니다.
- **`core/`** — 프레임워크에 종속되지 않는 인프라 코드. 설정 로드, 로깅 구성,
  도메인 예외(`AppError`) 등 어디서든 import 해도 안전한 모듈만 둡니다.
- **`db/`** — SQLAlchemy 엔진/세션과 `Base`. **여기서 다루는 것은 외부 위협
  피드 캐시뿐입니다.** 비즈니스 엔티티(User, Link, Directory 등)는 만들지
  마세요. SQLite 전용 PRAGMA(`WAL`, `foreign_keys=ON`, `synchronous=NORMAL`)
  가 연결마다 자동 적용됩니다.
- **`models/`** — ORM 모델. 새 모델을 추가하면 반드시
  `app/models/__init__.py` 에서 import 해야 Alembic autogenerate 가 인식합니다.
- **`schemas/`** — 요청·응답 Pydantic 모델. Spring 으로 보내는 분석 결과 DTO
  (`AnalysisResultCallback`) 도 여기서 정의합니다.
- **`services/`** — 4단계 파이프라인, 외부 API 클라이언트, 점수 산출, Spring
  콜백 호출, AI 정적 분석 호출 등 모든 비즈니스 로직. `Request` 같은 FastAPI
  객체를 받지 않고 `AsyncSession` / 순수 인자만 받습니다.
- **`middleware/`** — `RequestContextMiddleware` 가 매 요청마다 `X-Request-ID`
  를 생성/전파하고 structlog contextvars 에 바인딩합니다. 응답 헤더로도 echo
  되며 모든 로그 라인에 자동으로 따라붙습니다.
- **`alembic/`** — SQLite 의 제한적 ALTER 지원을 보완하기 위해
  `render_as_batch=True` 로 동작합니다.

---

## 핵심 — URL 안전성 분석 4단계 파이프라인

```
URL 입력 (Spring 으로부터 위임)
   │
   ▼
1단계: URL 정규화 + 단축 URL 언체이닝 ← 스킴·호스트 소문자, 기본 포트/프래그먼트
   │                                    제거, 리다이렉트 체인 추적해 최종 URL 확정
   ▼
2단계: 외부 위협 DB 대조       ← GSB(API) + URLhaus(로컬 SQLite)
   │   (최종 URL 기준 대조 — 블랙리스트 매치 시 즉시 short-circuit 가능)
   │
   ▼
3단계: 도메인 휴리스틱 분석    ← RDAP(등록일·레지스트라), 오타 도메인, 패턴
   │
   ▼
4단계: 페이지 콘텐츠 정적 분석 ← BeautifulSoup + AI API (피싱 신호 추론)
   │
   ▼
종합 위험 점수 산출 → 안전 / 주의 / 위험 판정
   │
   ▼
Spring `/internal/analysis-result` 콜백 POST
```

### 1단계 — URL 정규화 + 단축 URL 언체이닝

외부 DB 대조와 도메인 분석이 의미를 가지려면 **어떤 URL 을 검사할지부터
확정** 해야 합니다. `bit.ly` 같은 단축 URL 상태로 GSB / URLhaus 를 조회하면
거의 항상 매치되지 않기 때문에, 모든 후속 단계의 입력이 되는 "최종 URL"
을 먼저 만듭니다.

- **정규화**: 스킴·호스트 소문자화, 기본 포트(`:80` / `:443`) 제거,
  프래그먼트(`#...`) 제거, 퍼센트 인코딩 정돈, 추적 파라미터(`utm_*` 등)
  정책적 제거, IDN(퓨니코드) → 유니코드 정규화
- **언체이닝**: `HEAD` 요청만으로 리다이렉트 체인(3xx Location) 을 끝까지
  따라가 **최종 분석 대상 URL** 을 확정합니다. 무한 루프 방지를 위해 방문한
  URL 을 추적하며, hop 수가 5 이상이면 자체적으로 의심 신호로 가산합니다.
- 이후 2~4 단계는 모두 이 **최종 URL** 을 기준으로 동작합니다.

### 2단계 — 외부 위협 DB 대조

1단계에서 확정된 최종 URL 을 두 개의 위협 피드와 병렬로 대조합니다. 자체
휴리스틱보다 먼저 실행해 이미 알려진 악성 URL 이면 조기에 `danger` 로
short-circuit 할 수 있습니다.

| 소스 | 방식 | 응답 시간 | 탐지 대상 |
|------|------|-----------|-----------|
| **Google Safe Browsing** | Google API 실시간 조회 | 100~300ms | 피싱 / 멀웨어 / 소셜 엔지니어링 |
| **URLhaus (abuse.ch)** | CSV → **로컬 SQLite** 캐시 | 1~5ms | 멀웨어 배포 URL |

URLhaus 데이터는 APScheduler 가 주기적으로 CSV 를 다운로드해 로컬 SQLite 에
upsert 합니다. 분석 시에는 외부 호출 없이 로컬 인덱스만 조회합니다. 두 소스
중 하나라도 매치되면 그 자체로 강한 위험 신호이며, 점수 가산과 함께 후속
단계에 결과를 그대로 전달합니다.

### 3단계 — 도메인 휴리스틱 분석

규칙 기반 점수표로 도메인의 위험 신호를 합산합니다. 도메인 등록 정보는
**RDAP (RFC 7480~7484)** 로 조회합니다.

| 검사 항목 | 위험 신호 예시 | 점수 |
|----------|----------------|------|
| 오타 도메인 (레벤슈타인 거리 1~2) | `naverr.com`, `naaver.com` | +30 |
| 신규 도메인 (RDAP 등록 30일 미만) | `created_date` 기준 | +25 |
| IP 직접 접근 | `http://192.168.x.x/login` | +40 |
| 특수문자·하이픈 과다 | `login-secure-naver-auth.com` | +20 |
| 서브도메인 과다 중첩 | `signin.auth.naver.attacker.xyz` | +35 |
| HTTPS 미사용 (로그인 페이지) | `http://` | +15 |
| 합법 호스팅 플랫폼 (가산) | `github.io`, `netlify.app` | +15 |
| 오픈 리다이렉트 파라미터 | `?url=`, `?redirect=` | +35 |

레벤슈타인 거리 함수는 외부 라이브러리에 의존하지 않고 직접 구현합니다 (DP).
RDAP 응답은 도메인 단위로 인메모리 캐싱(24h) 하여 동일 도메인 재조회 비용을
줄입니다.

### 4단계 — 페이지 콘텐츠 정적 분석

`requests + BeautifulSoup` 으로 실제 페이지를 크롤링해 HTML 구조를 추출하고,
**AI(모델 미정) API** 가 피싱 신호를 정적으로 추론합니다. AI 는 본 엔진 안에서
이 정적 분석 단계에서만 사용됩니다.

추출 / 점수화하는 신호:

- **로그인 폼 + 브랜드 위장**: `<input type="password">` 가 있고 title 에는
  유명 브랜드명이 있는데 도메인은 그 브랜드와 무관 (+50)
- **브랜드 로고 이미지 위장**: `<img alt="...">` 의 alt 텍스트와 도메인 불일치 (+30)
- **`meta refresh` 자동 리다이렉트** (+20)
- **외부 링크 비율 과다**: 80% 이상이 외부 도메인이면 (+15)
- **AI 정적 추론**: 추출된 텍스트·폼·메타데이터를 AI 에게 넘겨 "이 페이지가
  특정 브랜드를 사칭하거나 자격 증명을 탈취하려 하는지" 여부와 근거 텍스트를
  반환받아 점수에 반영
- 페이지 접근 실패 시 +20 점 (의심 신호로 취급)

### 최종 점수 산출

각 단계의 점수를 합산해 다음 구간으로 매핑합니다.

| 합산 점수 | verdict | UI |
|-----------|---------|----|
| 0 ~ 30 | **safe** (안전) | 초록 — 정상적으로 열기 가능 |
| 31 ~ 60 | **caution** (주의) | 노랑 — 이유 표시 후 사용자 판단 |
| 61 이상 | **danger** (위험) | 빨강 — "피싱 의심, 열지 마세요" |

판정 결과와 함께 **"왜 위험한지 이유"** (`reasons` 배열) 를 반환해 사용자가
판단 근거를 이해할 수 있게 합니다.

---


## 시스템 한계와 보완 방안

어떤 정적 분석 시스템도 100% 탐지는 불가능합니다. 본 엔진이 인지하고 있는
주요 한계와 대응 방안은 다음과 같습니다.

| 공격 방식 | 한계 | 대응 방안 |
|----------|------|----------|
| 지연 활성화 (TOCTOU) | 분석 후 피싱 페이지로 교체 | 클릭 직전 재검사 + 리마인드 시 재검사 |
| 봇 탐지 | 크롤러엔 정상 페이지 반환 | User-Agent 주기적 교체 |
| 합법 도메인 악용 (`github.io` 등) | 신뢰 도메인 위에 피싱 호스팅 | 호스팅 플랫폼 가산 점수 |
| 리버스 프록시 | 진짜 사이트를 실시간 프록시 | 도메인 불일치 경고 |
| 오픈 리다이렉트 | 합법 도메인 경유 후 피싱 | 리다이렉트 파라미터 감지 |

---

## 두 백엔드 간 통신 규약

분석 엔진은 **요청-응답 동기 호출이 아니라 콜백** 방식으로 Spring 과 통신합니다.
Spring 이 분석 위임 요청을 보내면, 본 엔진은 즉시 `analysisId` 를 반환하고
실제 결과는 분석이 끝난 뒤 Spring 의 내부 콜백 엔드포인트로 POST 합니다.

```
Spring                                FastAPI (본 엔진)
  │                                       │
  │  POST /api/v1/analyze                 │
  │  { analysisId, url }                  │
  ├──────────────────────────────────────►│
  │                                       │ (4단계 파이프라인 비동기 실행)
  │◄──── 202 Accepted                     │
  │      { analysisId, status: "queued" } │
  │                                       │
  │                                       │ (분석 완료)
  │  POST /internal/analysis-result       │
  │  X-Internal-Api-Key: <key>            │
  │  { ... AnalysisResultCallback ... }   │
  │◄──────────────────────────────────────┤
  │                                       │
  │  200 OK { received: true }            │
  ├──────────────────────────────────────►│
```

모든 호출에는 `X-Internal-Api-Key` 헤더가 포함되어야 하며, Spring 은 이 헤더가
없거나 값이 일치하지 않는 요청을 거부합니다. 외부에서 `/internal/*` 경로를
직접 호출할 수 없게 하기 위함입니다. 이 값은 동적으로 발급·만료되는 토큰이
아니라, 두 백엔드가 환경변수로 공유하는 **정적 사전 공유 키(pre-shared key)**
입니다.

### Spring 콜백 메시지 정의

**Endpoint:** `POST {SPRING_INTERNAL_URL}/internal/analysis-result`

**Headers:**

| 헤더 | 필수 | 설명 |
|------|------|------|
| `Content-Type` | ✓ | `application/json` |
| `X-Internal-Api-Key` | ✓ | 두 백엔드가 환경변수로 공유하는 사전 공유 키 |
| `X-Request-ID` | ✓ | 원 요청의 request id 를 그대로 echo (분산 추적용) |

**Body — 성공 (`AnalysisResultCallback`):**

```json
{
  "analysisId": "9f0e0e3a-2c1f-4b76-9d3e-0e0a5a1cf2a1",
  "requestId":  "b4c3a9e7-7c2a-4a1d-9f0b-1c2d3e4f5a6b",
  "status":     "succeeded",
  "originalUrl": "https://bit.ly/abc123",
  "finalUrl":    "https://login-secure-naver-auth.com/signin",
  "verdict":     "danger",
  "score":       82,
  "reasons": [
    {
      "code":   "GSB_MATCH",
      "stage":  2,
      "weight": 50,
      "message": "Google Safe Browsing 에 SOCIAL_ENGINEERING 으로 등재된 URL"
    },
    {
      "code":   "TYPO_DOMAIN",
      "stage":  3,
      "weight": 30,
      "message": "naver.com 과 레벤슈타인 거리 2 의 유사 도메인"
    },
    {
      "code":   "BRAND_IMPERSONATION_FORM",
      "stage":  4,
      "weight": 50,
      "message": "비공식 도메인에서 NAVER 로그인 폼을 노출"
    }
  ],
  "stages": {
    "externalDb": {
      "gsb":      { "isThreat": true,  "matchedTypes": ["SOCIAL_ENGINEERING"] },
      "urlhaus":  { "isThreat": false, "host": "bit.ly" }
    },
    "unchain": {
      "hops": 2,
      "chain": [
        "https://bit.ly/abc123",
        "https://login-secure-naver-auth.com/signin"
      ]
    },
    "domainHeuristic": {
      "rdap": {
        "domain":         "login-secure-naver-auth.com",
        "registrar":      "NameCheap, Inc.",
        "createdDate":    "2026-03-22T00:00:00Z",
        "domainAgeDays":  16,
        "isNewDomain":    true
      },
      "signals": ["TYPO_DOMAIN", "NEW_DOMAIN", "HYPHEN_OVERUSE"]
    },
    "contentAnalysis": {
      "fetched":   true,
      "hasPasswordField": true,
      "aiVerdict": "phishing",
      "aiReason":  "페이지 제목과 로고 alt 텍스트가 NAVER 를 사칭하나, 도메인 소유자 정보가 일치하지 않음"
    }
  },
  "summary":      "NAVER 로그인 페이지를 사칭하는 신규 도메인입니다. 절대 자격 증명을 입력하지 마세요.",
  "engineVersion": "0.1.0",
  "analyzedAt":   "2026-04-07T05:42:11Z",
  "elapsedMs":    1843
}
```

**Body — 실패:**

```json
{
  "analysisId":  "9f0e0e3a-2c1f-4b76-9d3e-0e0a5a1cf2a1",
  "requestId":   "b4c3a9e7-7c2a-4a1d-9f0b-1c2d3e4f5a6b",
  "status":      "failed",
  "originalUrl": "https://bit.ly/abc123",
  "error": {
    "code":    "PIPELINE_TIMEOUT",
    "stage":   4,
    "message": "콘텐츠 분석 단계에서 30s 타임아웃 초과"
  },
  "engineVersion": "0.1.0",
  "analyzedAt":  "2026-04-07T05:42:41Z",
  "elapsedMs":   30000
}
```

**필드 정의:**

| 필드 | 타입 | 필수 | 설명 |
|------|------|------|------|
| `analysisId` | string (uuid) | ✓ | Spring 이 분석 위임 시 발급한 식별자. 콜백에서 그대로 echo |
| `requestId` | string (uuid) | ✓ | 분산 추적용 request id (`X-Request-ID` 헤더와 동일) |
| `status` | enum | ✓ | `succeeded` / `failed` |
| `originalUrl` | string | ✓ | Spring 에게서 받은 원본 URL |
| `finalUrl` | string | succeeded | 1·2단계를 거친 뒤 확정된 최종 분석 대상 URL |
| `verdict` | enum | succeeded | `safe` / `caution` / `danger` |
| `score` | int (0~100) | succeeded | 4단계 합산 점수 (100 cap) |
| `reasons[]` | array | succeeded | 점수에 기여한 신호들. UI 의 "이유" 배지에 그대로 사용 가능 |
| `reasons[].code` | string | ✓ | 머신 식별 코드 (예: `GSB_MATCH`, `TYPO_DOMAIN`, `NEW_DOMAIN`) |
| `reasons[].stage` | int (1~4) | ✓ | 어느 파이프라인 단계에서 발생했는지 |
| `reasons[].weight` | int | ✓ | 해당 신호가 더한 점수 |
| `reasons[].message` | string | ✓ | 사용자에게 보여줄 한국어 설명 |
| `stages` | object | succeeded | 단계별 원시 결과 (감사·디버깅 용) |
| `summary` | string | succeeded | Claude 가 만든 1~3문장 요약. UI 의 "이 링크는…" 카피로 사용 |
| `engineVersion` | string | ✓ | 본 엔진 버전. Spring 이 결과의 호환성을 판단할 때 사용 |
| `analyzedAt` | string (ISO8601 UTC) | ✓ | 분석 종료 시각 |
| `elapsedMs` | int | ✓ | 분석에 소요된 wall-clock 시간 (밀리초) |
| `error` | object | failed | 실패 원인 |

**Spring 측 응답:**

```json
HTTP/1.1 200 OK
{ "received": true }
```

- `200 OK` 외 응답 또는 네트워크 오류 시 본 엔진은 지수 백오프로 최대 3회
  재시도합니다. 그 후에도 실패하면 dead-letter 로그에 적재하고 운영자가
  수동 재처리할 수 있게 합니다.
- 동일 `analysisId` 의 콜백이 중복 도착할 수 있으므로, **Spring 측 처리는
  멱등(idempotent) 해야 합니다.**