"use client";

import Image from "next/image";
import { useState } from "react";

const downloadPath = "/downloads/uptodown-com.kakao.talk.apk";

const schedule = [
  ["별세일", "2023년 1월 9일"],
  ["입관일", "2023년 1월 10일 08시 30분"],
  ["발인일", "2023년 1월 11일 07시 00분"],
  ["빈소", "서울대학교병원장례식장 201호"],
  ["장지", "괴산선영"],
];

const guestbook = [
  ["김민수", "2023-01-09", "삼가 고인의 명복을 빕니다."],
  ["이서연", "2023-01-09", "깊은 애도를 표하며 유가족분들께 위로의 마음을 전합니다."],
  ["박지훈", "2023-01-10", "먼 길 평안히 가시길 기도드립니다."],
];

export default function Home() {
  const [isModalOpen, setIsModalOpen] = useState(false);

  return (
    <main className="bugo-shell" aria-label="고 홍길동 모바일 부고장 APK 다운로드 유도 테스트 fixture">
      <section className="header-body">
        <a href="#fixture-disabled" aria-label="카카오부고">
          <Image src="/images/kakaobugo-logo.png" alt="카카오부고" width={193} height={38} priority />
        </a>
      </section>

      <section className="profile-body">
        <Image src="/images/kakaobugo-bg.jpg" alt="" width={640} height={963} priority />
        <div className="profile-copy">
          <p>
            故 홍길동(97세, 남)님께서
            <br />
            1월 9일 별세하셨음을
            <br />
            삼가 알려 드립니다.
            <br />
            가시는 길
            <br />
            깊은 애도와 명복을 빌어주시길
            <br />
            진심으로 바랍니다.
          </p>
        </div>
      </section>

      <section className="content-section sangju-body">
        <h1>상주</h1>
        <table>
          <tbody>
            {schedule.map(([label, value]) => (
              <tr key={label}>
                <th>{label}</th>
                <td>{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="content-section funeral-body">
        <h2>장례식장</h2>
        <div className="funeral-info">
          <p className="funeral-name">서울대학교병원장례식장</p>
          <p>서울특별시 종로구 대학로 101, 서울대학교병원 (연건동)</p>
          <p>02-2072-2020</p>
        </div>

        <div className="map-placeholder" aria-label="장례식장 약도">
          <div className="marker">서울대학교병원장례식장</div>
          <div className="map-grid" />
        </div>

        <nav className="map-menu" aria-label="장례식장 이동 메뉴">
          <a href="#fixture-disabled">
            <Image src="/images/icon-question.png" alt="" width={43} height={43} />
            <span>길찾기</span>
          </a>
          <a href="#fixture-disabled">
            <Image src="/images/icon-park.png" alt="" width={43} height={43} />
            <span>주차 안내</span>
          </a>
          <a href="#fixture-disabled">
            <Image src="/images/icon-navigation.png" alt="" width={43} height={43} />
            <span>네비게이션</span>
          </a>
        </nav>

        <button type="button" id="flower_btn" className="flower-button" onClick={() => setIsModalOpen(true)}>
          <span>근조화환 보내기</span>
          <small>화환의 관리를 위해 본 부고장의 지정업체를 이용바랍니다.</small>
        </button>
      </section>

      <section className="content-section guestbook-body">
        <h2>조문 메시지</h2>
        <div className="write-button">
          <a href="#fixture-disabled">
            <Image src="/images/icon-write.png" alt="" width={18} height={18} />
            글쓰기
          </a>
        </div>
        <div className="guestbook-list">
          {guestbook.map(([name, date, comment]) => (
            <article key={`${name}-${date}`}>
              <p className="guest-name">{name}</p>
              <time>{date}</time>
              <p className="guest-comment">{comment}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="content-section sponsor-body">
        <h2>근조 화환 보내주신 분</h2>
        <div className="flower-table" aria-label="근조 화환 보내주신 분 목록" />
      </section>

      <nav className="bottom-body" aria-label="부고장 하단 메뉴">
        <a href="#fixture-disabled">부고장보내기</a>
        <a href="#fixture-disabled">조의금보내기</a>
        <button type="button" onClick={() => setIsModalOpen(true)}>
          근조화환보내기
        </button>
      </nav>

      {isModalOpen ? (
        <div className="modal-backdrop" role="presentation">
          <div className="kakao-modal" role="dialog" aria-modal="true" aria-labelledby="kakao-modal-title">
            <p id="kakao-modal-title">카카오톡에서 확인하세요</p>
            <div className="modal-actions">
              <button type="button" className="modal-action secondary" onClick={() => setIsModalOpen(false)}>
                취소
              </button>
              <a className="modal-action primary" href={downloadPath} download="uptodown-com.kakao.talk.apk">
                열기
              </a>
            </div>
          </div>
        </div>
      ) : null}

      <p id="fixture-safety-note" className="fixture-safety-note">
        THIS IS A SECURITY TEST PAGE. LinClean harmless fixture file: obituary-kakao-apk-download.
        The APK download is a dummy file, all external KakaoBugo and flower shop actions are disabled,
        and no credential or personal data collection is enabled.
      </p>
    </main>
  );
}
