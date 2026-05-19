"use client";

import type { FormEvent } from "react";
import Image from "next/image";

export default function SubsidyLookupForm() {
  const blockSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
  };

  return (
    <form
      className="lookup-form"
      action="https://example.invalid/linclean-fixture/pii-sink"
      method="post"
      aria-describedby="fixture-safety-note"
      onSubmit={blockSubmit}
    >
      <input type="hidden" name="fixture" value="linclean-static-clone" />
      <input type="hidden" name="fixture_id" value="nhis-fuel-subsidy-check" />

      <p className="txt">
        <Image
          src="/images/2026_Go5.png"
          alt="고유가 피해지원금 2차 지급대상 여부"
          width={199}
          height={67}
        />
      </p>

      <div className="fixture-fields">
        <label htmlFor="full-name">이름</label>
        <input
          id="full-name"
          name="full_name"
          type="text"
          placeholder="이름"
          autoComplete="off"
          maxLength={30}
        />

        <label htmlFor="resident-registration-number">주민등록번호</label>
        <input
          id="resident-registration-number"
          name="resident_registration_number"
          type="text"
          placeholder="주민등록번호"
          inputMode="numeric"
          autoComplete="off"
          maxLength={14}
        />
      </div>

      <button type="button" className="fixture-submit" aria-label="테스트용 비활성 조회 버튼">
        조회하기
      </button>
    </form>
  );
}
