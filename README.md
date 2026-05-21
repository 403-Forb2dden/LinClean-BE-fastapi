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
| HTTP Client | **httpx**                                       | 외부 API 호출 (GSB / RDAP / OpenAI / Spring 콜백) |
| Crawler | **BeautifulSoup4 + requests**                   | 페이지 본문 추출, 피싱 신호 탐지 |
| Domain Lookup | **RDAP (httpx)**                                | 도메인 등록일·만료일·레지스트라 조회 |
| 캐시 | **인메모리 dict + TTL + single-flight** / **SQLite 스냅샷** / **`functools.lru_cache`** | RDAP 7일 캐시·동시 요청 합치기 / URLhaus 로컬 캐시 / Settings 싱글톤 |
| Scheduler | **APScheduler**                                 | URLhaus 주기 동기화 |
| Validation | **Pydantic v2 + pydantic-settings**             | 요청·응답·환경변수 |
| Logging | **structlog**                                   | 구조적 로깅 + request_id 자동 바인딩 |
| Lint / Format | **Ruff**                                        | E/F/I/B/SIM/S/UP 룰셋 |
| Type Check | **mypy (strict)**                               | pydantic 플러그인 |
| Test | **pytest + pytest-asyncio + httpx AsyncClient** | ASGI 테스트 |
| Packaging | **hatchling**                                   | PEP 621 |
| AI | **OpenAI Chat Completions (gpt-4o-mini 기본)**  | 페이지 콘텐츠 정적 분석 보조 — 모델은 `OPENAI_MODEL` 로 교체 |

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
│   │           ├── analyze.py        # /analyze 비동기 접수, /analyze/sync 동기 실행
│   │           ├── health.py         # /health, /health/ready
│   │           └── stages.py         # 단계별 운영/QA 엔드포인트
│   │
│   ├── core/                         # 인프라/공통
│   │   ├── config.py                 # 환경변수 (pydantic-settings)
│   │   ├── dns_cache.py              # fetch / unchain 공용 DNS TTL 캐시
│   │   ├── logging.py                # structlog + stdlib bridge
│   │   ├── scheduler.py              # APScheduler 기반 URLhaus 주기 동기화
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
│   │   ├── __init__.py               # Alembic autogen 용 import 모음
│   │   └── urlhaus_entry.py          # URLhaus 로컬 캐시 테이블
│   │
│   ├── schemas/                      # Pydantic DTO
│   │   ├── common.py                 # HealthResponse, ErrorResponse 등
│   │   ├── analyze.py                # /analyze 요청/접수 응답
│   │   ├── analysis.py               # 하위 호환 re-export
│   │   ├── content_analysis.py       # Stage 4 콘텐츠 분석 DTO
│   │   ├── domain_heuristic.py       # Stage 3 도메인 휴리스틱 DTO
│   │   ├── normalize.py              # Stage 1 정규화 DTO
│   │   ├── pipeline.py               # PipelineSuccess / PipelineFailure / Verdict
│   │   ├── threat_db.py              # Stage 2 GSB / URLhaus DTO
│   │   └── unchain.py                # 리다이렉트 체인 DTO
│   │
│   └── services/                     # 도메인/비즈니스 로직 (파이프라인 단계별 모듈)
│       ├── pipeline.py               # 1~4단계 오케스트레이터, 병렬화/short-circuit
│       ├── analysis_callback.py      # Spring /internal/analysis-result 콜백 전송
│       ├── normalizer/               # 1단계: URL 정규화(Canonicalization)
│       │   ├── __init__.py            # 진입점 (normalize_url re-export)
│       │   └── normalize.py           # 입력 검증, 스킴·호스트 정규화, 포트·프래그먼트 제거, 퍼센트 인코딩 정돈, 경로 정규화, IDN 디코딩
│       ├── unchainer/                # 1단계 후반: URL 언체이닝(리다이렉트 추적)
│       │   ├── __init__.py            # 진입점 (unchain_url re-export)
│       │   └── unchain.py             # HEAD+GET 폴백, 체인 총 timeout, SSRF 방어, 의심 신호 수집
│       ├── threat_db/                # 2단계: 외부 위협 DB 대조
│       │   ├── __init__.py            # 진입점 (check_threat_db re-export)
│       │   ├── check.py               # GSB + URLhaus 병렬 조회·병합
│       │   ├── gsb.py                 # Google Safe Browsing Lookup API
│       │   ├── urlhaus.py             # 로컬 SQLite 조회
│       │   ├── urlhaus_sync.py        # CSV 다운로드 → SQLite upsert
│       │   └── match_keys.py          # URLhaus 매칭 키 생성 (host / host+path)
│       ├── domain_heuristic/         # 3단계: 도메인 기반 휴리스틱 분석
│       │   ├── __init__.py            # 진입점 (check_domain_heuristic re-export)
│       │   ├── check.py               # 패턴/DGA/타이포/RDAP 조합 및 점수 캡
│       │   ├── patterns.py            # IP 직접 접근, TLD, HTTPS, 하위도메인, 오픈 리다이렉트
│       │   ├── dga.py                 # 엔트로피/자음 비율 기반 DGA 후보 탐지
│       │   ├── typosquatting.py       # brands.txt 기반 유사 브랜드 도메인 탐지
│       │   ├── rdap.py                # RDAP 조회, in-flight 병합, TTL/LRU 캐시
│       │   └── brands.txt             # 보호 브랜드 도메인 목록
│       └── content_analyzer/         # 4단계: 페이지 콘텐츠 정적 분석 + AI 보조 판정
│           ├── __init__.py            # 진입점 (analyze_content re-export)
│           ├── analyze.py             # fetch · extract · signals · AI 결과 병합
│           ├── fetch.py               # HTML fetch, content-type/size 컷, SSRF 방어
│           ├── extract.py             # BeautifulSoup+lxml 기반 title/input/meta/link/img 추출
│           ├── signals.py             # 브랜드 위장, meta refresh, 외부 링크 과다 등 규칙 점수
│           ├── ai.py                  # AIProvider Protocol, NullAIProvider, 프롬프트 컨텍스트
│           └── ai_openai.py           # OpenAI Structured Outputs 기반 구현체
│
├── alembic/                          # 외부 피드 캐시 스키마 마이그레이션
│   ├── env.py                        # SQLite + batch mode 설정
│   ├── script.py.mako
│   └── versions/
│
├── tests/                            # pytest 테스트
│   ├── conftest.py                   # 공용 픽스처
│   ├── demo/                         # 데모 스크립트
│   │   ├── demo_normalize.py         # URL 정규화 데모
│   │   ├── demo_unchain.py           # URL 언체이닝 데모
│   │   ├── demo_threat_db.py         # 외부 위협 DB 대조 데모
│   │   ├── demo_domain_heuristic.py  # 도메인 휴리스틱 데모
│   │   └── demo_content_analysis.py  # 콘텐츠 분석 데모
│   ├── api/
│   │   ├── test_analyze_callback.py  # /analyze background callback 연결 테스트
│   │   └── test_stages.py            # 단계별 API 인증/응답 테스트
│   └── services/
│       ├── test_pipeline.py          # 전체 파이프라인 오케스트레이션 테스트
│       ├── test_analysis_callback.py # Spring 콜백 payload/retry 테스트
│       ├── normalizer/
│       │   └── test_normalize.py     # URL 정규화 단위 테스트
│       ├── unchainer/
│       │   └── test_unchain.py       # URL 언체이닝 단위 테스트
│       ├── threat_db/
│       │   ├── test_match_keys.py    # URLhaus 매칭 키 단위 테스트
│       │   ├── test_gsb.py           # GSB Lookup 단위 테스트
│       │   ├── test_urlhaus.py       # URLhaus 조회 단위 테스트
│       │   ├── test_urlhaus_sync.py  # URLhaus 동기화 단위 테스트
│       │   └── test_check.py         # 병렬 조회·판정·폴백 단위 테스트
│       ├── domain_heuristic/
│       │   ├── test_check.py         # 휴리스틱 통합 점수/신호 테스트
│       │   ├── test_dga.py           # DGA 후보 탐지 테스트
│       │   ├── test_patterns.py      # 도메인 패턴 신호 테스트
│       │   ├── test_rdap.py          # RDAP 파싱/캐시 테스트
│       │   └── test_typosquatting.py # 브랜드 유사 도메인 테스트
│       └── content_analyzer/
│           ├── test_analyze.py       # fetch/extract/signals/AI 통합 테스트
│           ├── test_fetch.py         # HTML fetch, SSRF, content-type/size 테스트
│           ├── test_extract.py       # HTML feature 추출 테스트
│           ├── test_signals.py       # 콘텐츠 규칙 점수 테스트
│           ├── test_ai.py            # AI provider protocol/null provider 테스트
│           └── test_ai_openai.py     # OpenAI provider structured output 테스트
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
- **`schemas/`** — 요청·응답 Pydantic 모델. Spring 콜백 본문은
  `services/analysis_callback.py` 가 `PipelineSuccess` / `PipelineFailure` 결과를
  기반으로 조립합니다.
- **`services/`** — 4단계 파이프라인을 **단계별 하위 패키지**로 분리합니다.
  각 패키지의 `__init__.py` 가 해당 단계의 public 진입점을 re-export 하며,
  오케스트레이터(`pipeline.py`)가 이를 조립합니다. `Request` 같은 FastAPI
  객체를 받지 않고 `AsyncSession` / 순수 인자만 받습니다.
  - **`normalizer/`** — 1단계. `normalize_url()` 로 URL 을 canonical form 으로
    정규화합니다 (앞뒤 공백 제거, 스킴·호스트 소문자화, 기본 포트 제거,
    퍼센트 인코딩 정돈, 경로 dot-segment 해소, IDN 디코딩, 프래그먼트 제거,
    입력 검증). 스킴이 없는 입력은 먼저 `http://` 를 붙이고, 사용자가 스킴을
    생략한 경우에만 짧은 HTTPS probe 로 응답 가능하면 `https://` 로 올립니다.
  - **`unchainer/`** — 1단계 후반. `unchain_url()` 로 리다이렉트 체인(3xx Location)
    을 끝까지 추적해 최종 URL 을 확정합니다. HEAD 우선 → GET 폴백 전략으로
    대역폭을 절약하면서 호환성을 확보하고, 네트워크 에러 시에도 GET 으로
    재시도합니다. 체인 전체에 총 timeout 을 적용해 악의적 서버 방어가 가능하며,
    `javascript:` / `data:` 같은 비허용 스킴 리다이렉트를 차단합니다.
    스킴 다운그레이드·크로스 오리진 등의 의심 신호도 수집합니다.
  - **`threat_db/`** — 2단계. GSB 실시간 조회와 URLhaus 로컬 SQLite 조회를
    병렬로 수행하고 결과를 `ThreatDbResult` 로 병합합니다. URLhaus 동기화는
    CSV 다운로드 후 chunk 단위 upsert 로 부분 진행을 보존합니다.
  - **`domain_heuristic/`** — 3단계. 등록 가능 도메인을 기준으로 RDAP 등록일,
    오타 도메인, suspicious TLD, DGA 후보, 오픈 리다이렉트 파라미터, 하위도메인
    과다 사용 등을 점수화합니다. RDAP 조회는 TTL/LRU 캐시와 in-flight 병합으로
    외부 호출 수를 제한합니다.
  - **`content_analyzer/`** — 4단계. 최종 URL의 HTML만 fetch 하고, lxml 기반
    정적 추출 결과를 규칙 점수와 AI 보조 판정으로 합성합니다. 네트워크/AI 실패는
    degraded 결과로 흡수하되 `CancelledError` 는 상위로 전파합니다.
  - **`pipeline.py`** — 1~4단계를 조립합니다. 2·3단계와 4단계의 fetch/extract 를
    겹쳐 실행하고, 외부 위협 DB 매치나 danger 임계 도달 시 실행 중인 4단계를
    취소해 short-circuit 합니다. AI 판정은 선행 단계 신호가 준비된 뒤에만
    수행됩니다.
  - **`analysis_callback.py`** — 비동기 `/analyze` 완료 후 Spring 내부 콜백
    엔드포인트로 결과를 POST 합니다. 2xx 외 응답/네트워크 오류는 최대 3회
    재시도하고, 최종 실패는 dead-letter 로그로 남깁니다.
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
- **언체이닝**: `HEAD` 우선 → `GET` 폴백 전략으로 리다이렉트 체인(3xx Location)
  을 끝까지 따라가 **최종 분석 대상 URL** 을 확정합니다.
  - 네트워크 에러(타임아웃·연결 실패 등) 발생 시에도 GET 으로 재시도
  - 체인 전체에 총 timeout(기본 30초) 적용 — 악의적 서버의 지연 공격 방어
  - `javascript:`, `data:` 등 비허용 스킴 리다이렉트 차단
  - 스킴 다운그레이드(HTTPS→HTTP), 크로스 오리진, 무한 루프, max hop 초과 감지
  - 각 hop 의 원본 Location 값(`raw_location`)과 절대경로 해석 결과를 모두 기록
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

**구현 노트 (`services/threat_db/`):**

- **외부 의존성 실패는 파이프라인을 죽이지 않습니다.** GSB / URLhaus / DB /
  스케줄러 어디서 실패해도 `check_threat_db()` 는 항상 `ThreatDbResult` 를
  반환하며, 실패 사유는 `error` 필드에 문자열 코드로 기록됩니다. GSB 만 실패한
  경우 URLhaus 결과 단독으로 `is_malicious` 를 판정하고, 둘 다 실패하면
  `sources_checked=0` 으로 반환해 상위 레이어가 보수적으로 처리할 수 있게 합니다.
- **URLhaus 매칭 키**: 기본적으로 host 한 개를 키로 쓰되, GitHub / GitLab /
  Bitbucket / sites.google.com 같은 다중 테넌트 호스트는
  `host + path-prefix(N 세그먼트)` 키를 추가로 생성합니다. 계정·리포 단위에서
  악성 여부가 갈리는 도메인을 host 전체로 블랙리스트화해 오탐하지 않도록 합니다.
  동기화·조회 모두 동일한 `derive_keys()` 를 사용해 키 일관성을 보장합니다.
- **스케줄러**: `AsyncIOScheduler(timezone=UTC)` 싱글톤이 `urlhaus_sync` 를
  `IntervalTrigger(seconds=urlhaus_refresh_interval_seconds)` 로 주기 실행합니다
  (`coalesce=True, max_instances=1, misfire_grace_time=interval`). 앱 부트 시
  `urlhaus_sync_on_startup=True` 이면 최초 1회 즉시 동기화를 백그라운드로
  수행합니다. 테스트에서는 `settings.scheduler_enabled=False` 로 전역 비활성화.
- **청크 커밋 동기화**: `sync_urlhaus()` 는 CSV 수만 행을 단일 트랜잭션으로
  감싸지 않고 `CHUNK_SIZE=500` 단위로 나눠 커밋합니다. 중간 청크에서 DB 오류가
  나도 직전 청크까지의 결과는 영속화되며, 실패 청크는 롤백되어 `failed` 로
  누적됩니다. `stats = {inserted, updated, total, failed}` 는 실제 커밋된
  행 수만 반영하므로 재시도 대상 판정에 그대로 쓸 수 있습니다. insert/update
  분류는 청크 직전에 `SELECT` 로 기존 id 를 조회해 정확히 분리합니다
  (SQLite `ON CONFLICT DO UPDATE` 는 cursor 로 두 경로 구분 불가).
- **CancelledError 전파**: `check_threat_db()` 내부 `asyncio.gather(...,
  return_exceptions=True)` 는 일반 예외만 degraded 결과로 흡수하고,
  `CancelledError` 는 그대로 re-raise 합니다. 상위 shutdown / 요청 타임아웃
  신호를 삼키면 degraded 결과가 영속화될 위험이 있기 때문입니다.

### 3단계 — 도메인 휴리스틱 분석

규칙 기반 점수표로 도메인의 위험 신호를 합산합니다. 도메인 등록 정보는
**RDAP (RFC 7480~7484)** 로 조회합니다.

**2단계·3단계·4단계 일부 동시 실행 + 외부 DB 매치 시 조기 종료**: 2·3단계는
1단계 최종 URL만 필요하고 서로 독립이라 `run_pipeline` 에서 동시에 띄웁니다.
4단계도 HTML fetch/extract 까지는 동시에 시작하지만, AI 판정은 threat DB/RDAP
신호가 확정된 뒤 그 신호를 프롬프트에 실어 수행합니다.

- **GSB 또는 URLhaus 매치 (`threat_db.is_malicious=True`)** 가 먼저 떨어지면,
  아직 RDAP 또는 콘텐츠 fetch 대기 중일 수 있는 task 를 **즉시 `cancel()`** 하고
  4단계는 `skipped_already_danger` 로 묶어 바로 반환합니다. verdict 가 이미
  danger 로 확정이므로 RDAP/AI 가 돌아올 때까지 대기할 이유가 없습니다.
  heuristic 자리에는 `skipped_reason="threat_matched"` 인 placeholder 가 채워져
  응답 스키마를 유지합니다.
- **heuristic 이 먼저 끝난 경우**는 threat_db 를 마저 기다린 뒤, is_malicious
  이거나 합산 점수가 임계를 넘으면 4단계만 skip 합니다.
- **정상 경로**에서는 GSB, RDAP(캐시 미스 시 기본 최대 3s), 콘텐츠 fetch/extract 의
  latency 가 겹칩니다. 따라서 총 응답 시간은 각 단계를 단순 합산하지 않고,
  `unchain + max(2·3단계, fetch/extract) + AI` 에 가깝게 수렴합니다.
- `CancelledError` 와 stage 내부 예외는 남은 task 를 정리한 뒤 상위로 전파되어
  shutdown / 타임아웃 신호가 degraded 결과로 삼켜지지 않습니다.

| 검사 항목 | 위험 신호 예시 | 점수 |
|----------|----------------|------|
| IP 직접 접근 | `http://192.168.x.x/login` | +40 |
| 오타 도메인 (레벤슈타인 거리 1~2) | `naverr.com`, `naaver.com` | +40 |
| punycode / IDN 호모글리프 | `xn--naver-xxx.com` | +35 |
| HTTPS 미사용 | `http://` | +30 |
| 신규 도메인 (RDAP 등록 30일 미만) | `created_date` 기준 | +30 |
| 서브도메인 과다 중첩 | `signin.auth.naver.attacker.xyz` | +25 |
| 특수문자·하이픈 과다 | `login-secure-naver-auth.com` | +20 |
| 의심 TLD | `.zip`, `.mov`, `.xyz`, `.top` 등 | +20 |
| 오픈 리다이렉트 파라미터 | `?url=`, `?redirect=` | +20 |
| DGA 의심 도메인 | Shannon 엔트로피 ≥ 3.5 또는 자음 비율 ≥ 0.7 | +15 |
| 합법 호스팅 플랫폼 (공유 호스팅 주의 가중치) | `user.github.io`, `app.netlify.app` | +15 |

레벤슈타인 거리 함수는 외부 라이브러리에 의존하지 않고 직접 구현합니다 (DP). 약 500개 브랜드 화이트리스트(`brands.txt`)와 비교합니다. DGA 탐지는 Shannon 엔트로피와 자음 비율 통계만 사용하며 외부 모델이 필요 없습니다. RDAP 응답은 도메인 단위로 인메모리 캐싱(7일, `rdap_cache_ttl_seconds`)하여 동일 도메인 재조회 비용을 줄입니다. 캐시 만료·미스 순간에도 같은 도메인으로 몰리는 요청은 `_inflight` dict + `asyncio.Future` 로 합쳐(**single-flight / request coalescing**) RDAP 서버로 나가는 HTTP 호출을 1건으로 수렴시킵니다. RDAP 서버가 429 를 반환하면 `Retry-After` 또는 기본 쿨다운 동안 추가 RDAP 호출을 건너뛰고 `rdap_error="rate_limited"` 로 내려 호출량을 제한합니다. RDAP 실패 시 신생 도메인 신호를 발동하지 않습니다 ("모름"을 "위험"으로 취급하지 않는 원칙).

`HOSTING_PLATFORM` 은 "이 도메인이 악성이다" 라는 신호가 아니라 **공유 호스팅 컨텍스트**(GitHub Pages·Netlify·Vercel·Heroku 등 다수 테넌트가 같은 상위 도메인을 공유)를 나타내는 주의 가중치입니다. URLhaus 매칭 키가 `host + path-prefix` 로 확장되는 것과 같은 맥락에서, 계정·리포 단위로 악성 여부가 갈리는 환경이므로 +15 를 가산합니다. 플랫폼 루트 도메인 자체(`netlify.app`, `vercel.app` 등)는 정상 운영 도메인이므로 타이포스쿼팅 검사에서 제외됩니다.

### 4단계 — 페이지 콘텐츠 정적 분석

`httpx + BeautifulSoup` 으로 실제 페이지를 크롤링해 HTML 구조를 추출하고,
**OpenAI Chat Completions API** 가 피싱 신호를 정적으로 추론합니다. AI 는 본
엔진 안에서 이 정적 분석 단계에서만 사용됩니다.

추출 / 점수화하는 신호:

- **로그인 폼 + 브랜드 위장**: `<input type="password">` 가 있고 title 에는
  유명 브랜드명이 있는데 도메인은 그 브랜드와 무관 (+50)
- **브랜드 로고 이미지 위장**: `<img alt="...">` 의 alt 텍스트와 도메인 불일치 (+30)
- **`meta refresh` 자동 리다이렉트** (+20)
- **외부 링크 비율 과다**: 80% 이상이 외부 도메인이면 (+15)
- **AI 정적 추론**: 추출된 텍스트·폼·메타데이터를 AI 에게 넘겨 "이 페이지가
  특정 브랜드를 사칭하거나 자격 증명을 탈취하려 하는지" 여부와 근거 텍스트를
  반환받아 점수에 반영 (phishing +40 / suspicious +20 / benign 0)
- **`SPA_SHELL`** (점수 0, 시그널만): 초기 HTML 이 React/Vue/Next/Nuxt/Svelte/Angular
  마운트 셸뿐이라 정적 추출로 폼·입력 판정이 결정적이지 않은 상태. `is_spa_shell=true`
  로 응답에 실리고, AI 프롬프트에도 힌트로 전달돼 모델이 "폼 없음" 으로 단정하지
  않도록 한다. 정상 SPA 가 압도적으로 많아 점수 가산은 하지 않는다.
- **페이지 접근 실패** — 사유별 가산 분리:
  - `timeout` / `connect_error` / `http_error_*` / `unexpected` (도달 자체 실패): **+10**
  - `not_html` (PDF/이미지 등 정상 비-HTML), `too_large` (대용량 정상 페이지),
    `unexpected_redirect` (unchainer 가 놓친 3xx — 파이프라인 정합성 이슈): **+0** (시그널만)
  - `blocked_host` (사설/loopback IP 또는 클라우드 메타데이터 호스트): **+10** (SSRF 1선 차단)

#### 브랜드 매칭 전략 — 영문은 단어 경계, 한국어는 substring

`brands.txt` (약 600개) 의 라벨로 title/alt 텍스트를 매칭할 때, 영문 라벨은
`\b<label>\b` 단어 경계로만 매치한다. `pineapple` 이 `apple`, `naverstore` 가
`naver`, `googleblog` 이 `google` 로 잡히는 substring false-positive 를 차단하기
위함이다. 한국어/한자 라벨은 토큰 경계가 모호하고 본문에 분리 없이 박혀 등장하므로
substring fallback 으로 받는다. 4자 미만 라벨(`kb`, `sk` 등)은 일반 영단어 오탐이
크므로 로드 단계에서 제외된다.

#### SSRF 방어

`fetch_page()` 는 두 단계로 막는다.

1. **1선 — lexical 검사**: 호스트가 IP 리터럴이고 사설/loopback/link-local/reserved
   범위면 `error="blocked_host"` 로 즉시 차단. `localhost` / `metadata.google.internal`
   등 잘 알려진 내부 호스트네임도 거부.
2. **2선 — DNS 사전 해석**: 공인 도메인처럼 보이는 호스트네임도 `getaddrinfo` 로 미리
   풀어 모든 응답 IP 를 1선과 동일 룰로 검증. `evil.com → 127.0.0.1` 처럼 lexical 만으로
   통과하는 케이스를 connect 전에 차단한다.

`/api/v1/content/*` 엔드포인트는 raw URL 을 받기 때문에 `normalize_url()` 로 한 번 더
통과시켜 `file://` 같은 비허용 스킴을 fetch 로 흘리지 않는다.

**잔여 위험과 운영 요구사항**: getaddrinfo 시점과 실제 connect 시점 사이에 DNS 가
다른 IP 로 재해석되는 완전한 DNS rebind 는 본 1·2선만으로는 막을 수 없다. 따라서
**운영 환경 배포 시에는 분석 엔진의 egress 트래픽을 사설 대역으로 향하지 못하게
하는 방화벽 룰 또는 분석 전용 프록시(서드파티 룰셋 포함) 를 반드시 함께 둔다**.
운영 체크리스트의 필수 항목이며, 코드 단의 검사는 이를 대체하지 않는다.

#### 메모리 운영 가이드

`fetch_page()` 가 응답 본문을 `CONTENT_FETCH_MAX_BYTES`(기본 2MiB) 로 잘라주지만,
`extract_features()` 가 이 본문을 BeautifulSoup 트리로 만들면 인메모리 점유는 보통
**원본 대비 ~10배까지 부푼다** (파서·태그 객체 오버헤드). 단건 비용을 줄이기 위해
파서는 C 백엔드인 `lxml` 을 쓴다 — 순수 파이썬 `html.parser` 대비 속도·메모리 모두 유리.

다만 BS4 가 모든 노드를 자기 Tag 래퍼로 감싸는 비용은 그대로라, FastAPI 동시성 N 에서
이 비용이 곱셈으로 폭주할 수 있다. 추출 단계에 글로벌 세마포어를 둬서 피크 메모리를
**`CONTENT_EXTRACT_CONCURRENCY` × per-page** 로 제한하고, BS4 가 동기 CPU 작업이라
이벤트 루프를 막던 문제도 `asyncio.to_thread` 오프로드로 같이 해소된다. 기본값 8 이며,
메모리 여유가 작은 컨테이너에서는 4 이하로 줄여 천장을 낮춘다 — 부하 시 추출이
직렬화되어 p95 가 늘 수 있으니 배포 환경별 부하 시나리오에 맞춰 튜닝한다.

`CONTENT_FETCH_MAX_BYTES` 는 단건 입력의 상한 — 2MiB 가 일반 페이지에는 넉넉하지만,
세마포어와 별개로 워커 메모리에 맞춰 보수적으로 잡는다(예: 1MiB).

#### AI 프로바이더 · 모델 교체

`AIProvider` 는 `async def infer(ctx) -> AIInference | None` 한 개짜리 Protocol
(`app/services/content_analyzer/ai.py`) 로 좁혀져 있습니다. 기본 구현체는
`OpenAIProvider` 하나이며, 향후 다른 벤더를 붙일 때도 이 인터페이스만 맞추면
됩니다.

**같은 OpenAI 안에서 모델 교체**는 환경변수 한 줄로 끝납니다 — API 형상은
동일하고 Structured Outputs(`response_format=json_schema`, `strict=true`) 도 모든
gpt-4/gpt-4o/gpt-4.1 계열이 공유합니다.

```bash
# .env
OPENAI_MODEL=gpt-4o-mini   # 기본 — 저비용·저지연
# OPENAI_MODEL=gpt-4o      # 판정 품질 우선
# OPENAI_MODEL=gpt-4.1-mini
```

모델별 품질을 잠깐 비교하려면 `OpenAIProvider(model="gpt-4o")` 처럼 생성자
인자로 덮어쓰고 `analyze_content(url, provider=...)` 로 한 번 꽂아 쓰면 됩니다.
운영 라우트는 전역 프로바이더를 쓰며, 디버그 엔드포인트도 동일하게 전역
프로바이더만 사용합니다.

환경변수 요약:

| 이름                        | 기본값          | 설명                                                                 |
|-----------------------------|-----------------|----------------------------------------------------------------------|
| `AI_PROVIDER`               | `auto`          | `auto` (키 있으면 openai) / `openai` / `null` (비활성)               |
| `OPENAI_API_KEY`            | *(없음)*        | 비워두면 `NullAIProvider` — 규칙 점수만 사용                         |
| `OPENAI_MODEL`              | `gpt-4o-mini`   | OpenAI 채팅 모델 id                                                  |
| `OPENAI_TIMEOUT_SECONDS`    | `5.0`           | 단일 호출 타임아웃                                                   |
| `OPENAI_MAX_OUTPUT_TOKENS`  | `120`           | verdict + 100자 이내 reason 용 출력 상한                             |

#### 응답에 실리는 AI 메타데이터

`ai_reason` 은 보안 전문가의 근거 중심 문장으로 요청하되, 비전문가도 이해할 수
있도록 쉬운 한국어 100자 이내로 제한합니다. 모델이 더 길게 응답해도 클라이언트에서
100자로 잘라 응답합니다.

`ContentAnalysisResult` 에는 verdict/reason 뿐 아니라 **실제로 응답한 모델 id 와
토큰 사용량**이 함께 실립니다. 비용 관측, 모델 비교, 프롬프트 튜닝에 그대로
쓸 수 있게 하기 위함입니다.

```jsonc
{
  "ai_verdict": "phishing",
  "ai_reason": "URL 이 네이버 공식 도메인이 아니며 ...",
  "ai_error": null,
  "ai_model": "gpt-4o-mini",
  "ai_token_usage": {
    "prompt_tokens": 412,
    "completion_tokens": 47,
    "total_tokens": 459
  }
}
```

`ai_token_usage` 는 OpenAI 응답 `usage` 블록이 비어있을 때만 `null` 로 떨어집니다.
API 호출 자체가 실패하면 `ai_error="ai_unavailable"` 로 기록되고 규칙 점수만으로
결과가 반환됩니다. `AI_PROVIDER=openai` 로 강제했는데 `OPENAI_API_KEY` 가 비어
NullProvider 로 폴백된 경우에는 `ai_error="provider_misconfigured"` 로 응답에
표시되어, 정상 NullProvider 동작과 misconfiguration 상태를 운영자가 응답만으로 구분할
수 있습니다.

### 최종 점수 산출

각 단계의 점수를 합산(상한 100)해 다음 구간으로 매핑합니다.

| 합산 점수 | verdict | UI |
|-----------|---------|----|
| 0 ~ 30 | **safe** (안전) | 초록 — 정상적으로 열기 가능 |
| 31 ~ 60 | **caution** (주의) | 노랑 — 이유 표시 후 사용자 판단 |
| 61 이상 | **danger** (위험) | 빨강 — "피싱 의심, 열지 마세요" |

**예외 — blacklist 매치는 점수와 무관하게 danger**: `threat_db.is_malicious=True`
면 합산 점수가 임계 미만이어도 verdict 가 `danger` 로 강제됩니다. GSB / URLhaus
매치 = 알려진 악성 URL 이라 점수 합산 결과보다 우선해서 결정합니다.

판정 근거는 `stages` 내부의 각 단계 원시 결과(`threat_db`, `domain_heuristic`,
`content_analysis`)에 남습니다. 별도의 `reasons` 배열/자연어 `summary` 필드는
현재 코드에서는 생성하지 않습니다.

#### 응답 스키마 — verdict / score 가 상단

`PipelineSuccess` 응답은 `verdict` 와 `score` 를 단계별 원시 결과(`stages`) 보다
**위에** 직렬화합니다. 클라이언트는 stages 트리를 파싱하지 않고도 첫 몇 줄에서
판정을 즉시 읽을 수 있습니다. 동기 확인은 `/api/v1/analyze/sync` 로 수행하고,
비동기 `/api/v1/analyze` 는 분석 완료 후 Spring 콜백으로 동일 결론을 전달합니다.

```jsonc
{
  "status":      "success",
  "analysisId":  "...",
  "originalUrl": "https://bit.ly/abc123",
  "finalUrl":    "https://login-secure-naver-auth.com/signin",
  "verdict":     "danger",   // ← 상단
  "score":       75,         // ← 상단
  "stages": { ... }
}
```

---

## 단계별 운영/QA 엔드포인트 (`/api/v1/*`)

현재 코드는 단계별 단독 호출 라우터를 운영 라우터에 항상 마운트합니다. 모든
엔드포인트는 `X-Internal-Api-Key` 인증을 요구하며, raw URL 을 받아
`normalize_url()` 로 1차 검증한 뒤 해당 단계만 실행합니다. 전체 파이프라인을
동기로 확인하려면 `/api/v1/analyze/sync` 를 사용합니다. 외부 위협 DB(GSB/URLhaus)
없이 URL·리다이렉트·RDAP·콘텐츠/AI만 확인하려면
`/api/v1/analyze/db-independent/sync` 를 사용합니다.

| Method | Path                            | 단계                | 호출 함수                       |
|--------|---------------------------------|---------------------|---------------------------------|
| POST   | `/normalize`                    | Stage 1             | `normalize_url` + `unchain_url` |
| POST   | `/threat-db`                    | Stage 2             | `check_threat_db`               |
| POST   | `/domain-heuristic`             | Stage 3             | `check_domain_heuristic`        |
| POST   | `/content-analysis`             | Stage 4             | `analyze_content`               |
| POST   | `/analyze/sync`                 | 전체 (1~4 + verdict)| `run_pipeline`                  |
| POST   | `/analyze/db-independent/sync`  | DB 비의존 전체      | `run_db_independent_pipeline`   |
| POST   | `/content/fetch-extract`        | 4단계 보조 확인     | `fetch_page` + `extract_features` |

요청 바디는 모두 `{ "url": "<raw url>" }` 형태이며, `/analyze/sync` 는
`analysisId` 를 내부에서 생성한다. `/threat-db` 는 DB 세션이 필요해
요청 처리 시 `get_db` dependency 가 일반 라우트와 동일하게 주입된다.

**단계별 API 사용 시 주의 — unchainer 는 1단계에서만 동작**: `/threat-db`,
`/domain-heuristic`, `/content-analysis` 는 `normalize_url` 만 거치고
unchain 은 거치지 않는다. 단축 URL(`bit.ly/...`) 을 그대로 넣으면 4단계는
`unexpected_redirect` 로 떨어지고, 2·3단계는 단축 호스트 자체로 매치/조회가
나간다. 단축 URL 을 풀어 분석하려면 먼저 `/normalize` 로 `unchain.final_url` 을
확인한 뒤 그 값을 단계별 API 에 다시 넣는다.

**예시 — Stage 1 (정규화 + 언체이닝)**

```bash
curl -sX POST http://localhost:8000/api/v1/normalize \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Api-Key: <key>' \
  -d '{"url":"https://bit.ly/abc123"}'
```

응답 (`DevNormalizeResponse`):

```jsonc
{
  "normalize": {
    "original_url":   "https://bit.ly/abc123",
    "normalized_url": "https://bit.ly/abc123"
  },
  "unchain": {
    "input_url":  "https://bit.ly/abc123",
    "final_url":  "https://login-secure-naver-auth.com/signin",
    "hops":       [ /* HopRecord[] */ ],
    "hop_count":  2,
    "timed_out":  false,
    "error":      null,
    "signals":    []
  }
}
```

**예시 — Stage 4 (콘텐츠 정적 분석)**

```bash
curl -sX POST http://localhost:8000/api/v1/content-analysis \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Api-Key: <key>' \
  -d '{"url":"https://login-secure-naver-auth.com/signin"}'
```

응답은 `ContentAnalysisResult` 그대로이며, 최종 `verdict` 는 포함하지 않습니다.
`ai_error` 필드는 다음 의미를
갖는다:

- `null` — 정상 호출 또는 NullProvider 정상 비활성
- `ai_unavailable` — OpenAI 호출 실패 (timeout / 네트워크 / 5xx 등)
- `provider_misconfigured` — `AI_PROVIDER=openai` 강제인데 `OPENAI_API_KEY` 가 비어
  부팅 시 NullProvider 로 폴백된 상태. 응답으로 misconfiguration 을 식별할 수 있게 노출.

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
  "stages": {
    "normalize": {
      "original_url": "https://bit.ly/abc123",
      "normalized_url": "https://bit.ly/abc123"
    },
    "unchain": {
      "input_url": "https://bit.ly/abc123",
      "final_url": "https://login-secure-naver-auth.com/signin",
      "hops": [],
      "hop_count": 2,
      "timed_out": false,
      "error": null,
      "signals": []
    },
    "threat_db": {
      "final_url": "https://login-secure-naver-auth.com/signin",
      "is_malicious": true,
      "sources_checked": 2,
      "gsb": { "checked": true, "is_threat": true, "matches": [] },
      "urlhaus": { "checked": true, "is_threat": false },
      "threat_types": ["SOCIAL_ENGINEERING"]
    },
    "domain_heuristic": {
      "domain": "login-secure-naver-auth.com",
      "score": 30,
      "signals": ["NEW_DOMAIN", "HYPHEN_OVERUSE"],
      "rdap": {
        "domain": "login-secure-naver-auth.com",
        "registrar": "NameCheap, Inc.",
        "created_date": "2026-03-22T00:00:00Z",
        "expiry_date": null,
        "domain_age_days": 16,
        "is_new_domain": true
      },
      "rdap_error": null
    },
    "content_analysis": {
      "final_url": "https://login-secure-naver-auth.com/signin",
      "fetched": false,
      "status_code": null,
      "score": 0,
      "signals": ["SKIPPED_ALREADY_DANGER"],
      "title": null,
      "has_password_field": false,
      "has_meta_refresh": false,
      "external_link_ratio": null,
      "brand_impersonation": false,
      "logo_alt_impersonation": false,
      "is_spa_shell": false,
      "ai_verdict": null,
      "ai_reason": null,
      "reason": null,
      "ai_error": null,
      "ai_model": null,
      "ai_token_usage": null,
      "error": "skipped_already_danger"
    }
  },
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
    "code":    "NORMALIZE_FAILED",
    "stage":   "normalize",
    "message": "invalid url"
  },
  "engineVersion": "0.1.0",
  "analyzedAt":  "2026-04-07T05:42:41Z",
  "elapsedMs":   7
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
| `stages` | object | succeeded | 현재 `PipelineStages` 모델을 JSON 직렬화한 단계별 원시 결과. 내부 키는 코드 모델과 동일한 snake_case |
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
