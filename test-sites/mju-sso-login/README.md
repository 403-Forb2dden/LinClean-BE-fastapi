# MJU SSO Login Test Site

Static clone of the Myongji University SSO login page for LinClean URL quarantine testing.

## Source

`https://sso.mju.ac.kr/sso/auth?response_type=code&client_id=lms&state=Random%20String&redirect_uri=https://lms.mju.ac.kr/ilos/sso/sso_response.jsp`

## Safety

- This fixture does not authenticate users.
- The login button is non-submitting.
- User input is not stored or sent externally.
- External account recovery, privacy, remote support, and PDF guide links are disabled.
- `robots.txt` disallows crawling and page metadata uses `noindex,nofollow`.

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
