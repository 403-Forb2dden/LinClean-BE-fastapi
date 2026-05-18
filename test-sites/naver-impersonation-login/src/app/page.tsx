"use client";

import Image from "next/image";

const recoveryLinks = ["아이디 찾기", "비밀번호 찾기", "회원가입"];
const socialProviders = ["Apple", "Google", "LINE"];

export default function Home() {
  return (
    <main className="naver-login-page">
      <section className="fixture-banner" aria-label="테스트 fixture 안내">
        THIS IS A SECURITY TEST PAGE. DO NOT USE REAL CREDENTIALS. LinClean test fixture:
        naver-impersonation-login.
      </section>

      <section className="login-shell" aria-label="NAVER 로그인 테스트 fixture">
        <nav className="language-list" aria-label="언어 선택">
          <a className="active" href="#fixture-disabled">
            한국어
          </a>
          <a href="#fixture-disabled">English</a>
          <a href="#fixture-disabled">中文</a>
        </nav>

        <a className="brand" href="#fixture-disabled" aria-label="NAVER">
          <Image src="/images/naver-logo.svg" alt="NAVER 로고" width={184} height={36} priority />
        </a>

        <form
          className="login-card"
          action="https://example.invalid/linclean-fixture/credential-sink"
          method="post"
          aria-describedby="fixture-safety-note"
          onSubmit={(event) => {
            event.preventDefault();
          }}
        >
          <input type="hidden" name="fixture" value="linclean-static-clone" />
          <input type="hidden" name="source" value="naver-impersonation-login" />

          <div className="login-tabs" role="tablist" aria-label="로그인 방식">
            <button className="tab active" type="button" role="tab" aria-selected="true">
              ID/전화번호
            </button>
            <button className="tab" type="button" role="tab" aria-selected="false">
              일회용 번호
            </button>
            <button className="tab" type="button" role="tab" aria-selected="false">
              QR코드
            </button>
          </div>

          <div className="input-group">
            <label className="visually-hidden" htmlFor="naver-user-id">
              아이디 또는 전화번호
            </label>
            <input
              id="naver-user-id"
              name="id"
              type="text"
              placeholder="아이디 또는 전화번호"
              autoComplete="off"
              maxLength={41}
            />
            <label className="visually-hidden" htmlFor="naver-password">
              비밀번호
            </label>
            <input
              id="naver-password"
              name="password"
              type="password"
              placeholder="비밀번호"
              autoComplete="off"
            />
          </div>

          <div className="login-options">
            <label className="keep-login">
              <span className="switch" aria-hidden="true" />
              로그인 상태 유지
            </label>
            <button type="button" className="ip-security" aria-pressed="true">
              IP보안 <strong>ON</strong>
            </button>
          </div>

          <button className="login-button" type="submit">
            로그인
          </button>

          <button className="passkey-button" type="button">
            패스키 로그인
          </button>

          <ul className="recovery-links" aria-label="계정 지원">
            {recoveryLinks.map((label) => (
              <li key={label}>
                <a href="#fixture-disabled">{label}</a>
              </li>
            ))}
          </ul>

          <div className="social-login" aria-label="소셜 로그인">
            <p>더욱 간편한 로그인</p>
            <div className="social-buttons">
              {socialProviders.map((provider) => (
                <button className={`social ${provider.toLowerCase()}`} key={provider} type="button">
                  <span aria-hidden="true">{provider.slice(0, 1)}</span>
                  {provider}
                </button>
              ))}
            </div>
          </div>
        </form>

        <footer className="login-footer">
          <ul>
            <li>
              <a href="#fixture-disabled">이용약관</a>
            </li>
            <li>
              <a href="#fixture-disabled">개인정보처리방침</a>
            </li>
            <li>
              <a href="#fixture-disabled">책임의 한계와 법적고지</a>
            </li>
            <li>
              <a href="#fixture-disabled">회원정보 고객센터</a>
            </li>
          </ul>
          <p>
            <strong>NAVER</strong> Copyright NAVER Corp. All Rights Reserved.
          </p>
        </footer>
      </section>

      <p id="fixture-safety-note" className="visually-hidden">
        THIS IS A SECURITY TEST PAGE. DO NOT USE REAL CREDENTIALS. This form is blocked
        client-side and does not call a real NAVER authentication endpoint.
      </p>
    </main>
  );
}
