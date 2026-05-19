# NHIS Fuel Subsidy Check Test Site

Static NHIS-style public agency impersonation fixture for LinClean URL quarantine testing.

## Source

`https://www.nhis.or.kr/`

## Scenario

The page presents a "고유가 피해지원금 대상 여부 조회" flow and asks for a name and resident registration number. It is intended to provide true-positive regression coverage for public-agency impersonation and PII collection signals.

## Safety

- This fixture does not submit, store, or transmit personal information.
- The form action points to `https://example.invalid/linclean-fixture/pii-sink`.
- Client-side submit handling calls `preventDefault()`.
- Lookup and navigation controls are disabled.
- `robots.txt` disallows crawling and page metadata uses `noindex,nofollow`.
- A hidden LinClean fixture marker is present in the page.

## Run

```bash
npm install
npm run dev
```

## Verify

```bash
npm run typecheck
npm run lint
npm run build
```
