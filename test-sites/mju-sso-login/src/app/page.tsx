import Image from "next/image";

const notices = [
  "최초 사용자는 주민등록 기재된 생년월일 6자리 입력 후 본인인증 절차를 거쳐 비밀번호를 변경해야 함",
  "아이디 : 학번/교번",
  "2012.07.10 이전 임용 교직원은 email ID를 통합로그인 ID로 사용하며, 교직원 번호로 로그인할 수 없습니다.",
];

export default function Home() {
  return (
    <main className="mju-sso-page">
      <section className="login-box" aria-label="명지대학교 통합로그인 테스트 fixture">
        <div className="login-top">
          <a className="logo" href="#fixture-disabled" aria-label="명지대학교">
            <Image src="/images/mju-logo.jpg" alt="명지대학교 로고이미지" width={700} height={180} priority />
          </a>
          <h1>
            통합로그인(SSO)
            <br />
            <span>Integrated Login</span>
          </h1>
        </div>

        <ul className="login-lan" aria-label="언어 선택">
          <li>
            <a className="on" href="#login-kr">KR</a>
          </li>
          <li>
            <a href="#login-en">EN</a>
          </li>
        </ul>

        <form className="login-form" aria-describedby="fixture-safety-note">
          <input type="hidden" name="fixture" value="linclean-static-clone" />
          <div id="login-kr" className="login-con active">
            <div className="id-pw-wrap">
              <div className="input-box">
                <input type="text" name="user_id" placeholder="아이디" title="아이디" maxLength={30} autoComplete="off" />
                <input type="password" name="pw" placeholder="비밀번호" title="비밀번호" autoComplete="off" />
              </div>
              <button type="button" className="login-bt" aria-label="테스트용 비활성 로그인 버튼">
                로그인
              </button>
            </div>

            <div className="keepid-box">
              <input type="checkbox" id="remember-me" title="아이디 저장" />
              <label htmlFor="remember-me">아이디 저장</label>
              <p className="capslock">Caps Lock이 켜져있습니다.</p>
            </div>

            <ul className="set-id">
              <li>
                <a href="#fixture-disabled" title="아이디 찾기">아이디 찾기</a>
              </li>
              <li>
                <a href="#fixture-disabled" title="비밀번호 찾기">비밀번호 변경</a>
              </li>
            </ul>

            <div className="notice dot-list">
              <div className="notice-heading">
                <h2 className="info">이용안내</h2>
                <button type="button" className="pdf-guide">2차인증 시행안내(교직원)</button>
              </div>
              <ul>
                {notices.map((notice) => (
                  <li key={notice}>{notice}</li>
                ))}
              </ul>
            </div>
          </div>
        </form>

        <ul className="service">
          <li>
            <a href="#fixture-disabled">개인정보처리방침</a>
          </li>
          <li>
            <a href="#fixture-disabled">원격지원</a>
          </li>
        </ul>
      </section>

      <p id="fixture-safety-note" className="fixture-safety-note">
        THIS IS A SECURITY TEST PAGE. DO NOT USE REAL CREDENTIALS. LinClean test fixture: mju-sso-login.
      </p>
    </main>
  );
}
