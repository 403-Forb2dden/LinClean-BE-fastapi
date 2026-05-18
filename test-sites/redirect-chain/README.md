# 리다이렉트 체인 테스트 사이트

LinClean URL 검역 엔진의 리다이렉트 추적을 검증하기 위한 테스트 사이트입니다.
모든 리다이렉트 응답은 이동이 발생한다는 것을 확인하기 쉽도록 0.5초 지연 후 반환됩니다.

## 경로

| 경로 | 기대 체인 |
| --- | --- |
| `/redirect/1` | `/final/safe` |
| `/redirect/3` | `/hop/1` -> `/hop/2` -> `/final/safe` |
| `/redirect/external` | `https://example.com/` |
| `/redirect/unsafe-scheme` | `javascript:alert(1)` Location 헤더 반환 |
| `/redirect/max-hop` | `/hop/max/1` -> ...; 기본 5 hop 제한 초과 |
| `/redirect/to-suspicious` | `/final/suspicious`; 비활성 카드 인증 폼 포함 |

`/redirect/unsafe-scheme`는 브라우저 보안 정책 때문에 화면 이동이 보이지 않을 수 있습니다.
이 경로는 `curl -I` 또는 엔진 응답의 `Location` 헤더로 확인하세요.

## 안전 장치

- 인증 정보를 수집하지 않습니다.
- 카드번호, CVC, 만료일, 카드 비밀번호 앞 2자리 입력 UI는 `readOnly`이며 `name` 속성이 없어 전송 데이터가 만들어지지 않습니다.
- 파일을 다운로드하지 않습니다.
- 실제 악성 인프라로 리다이렉트하지 않습니다.
- 비허용 스킴 경로는 언체이너의 스킴 차단 검증만을 위해 존재합니다.
- `robots.txt`와 page metadata로 검색 인덱싱을 차단합니다.

## 실행

```bash
npm install
npm run dev -- --port 3107
```

## 수동 확인

```bash
curl -I http://localhost:3107/redirect/1
curl -I http://localhost:3107/redirect/3
curl -I http://localhost:3107/redirect/external
curl -I http://localhost:3107/redirect/unsafe-scheme
curl -I http://localhost:3107/redirect/max-hop
curl -I http://localhost:3107/redirect/to-suspicious
```

다중 hop과 max-hop 동작은 다음처럼 확인할 수 있습니다.

```bash
curl -I -L http://localhost:3107/redirect/3
curl -I -L --max-redirs 5 http://localhost:3107/redirect/max-hop
```

## 검증

```bash
npm run typecheck
npm run lint
npm run build
```
