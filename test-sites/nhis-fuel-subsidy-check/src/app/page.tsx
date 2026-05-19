import Image from "next/image";
import SubsidyLookupForm from "@/components/subsidy-lookup-form";

export default function Home() {
  return (
    <main className="intro-wrap" aria-label="국민건강보험 고유가 피해지원금 테스트 fixture">
      <div className="intro-top">
        <h1>
          <Image src="/images/logo.png" alt="h-well 국민건강보험" width={141} height={48} priority />
        </h1>
        <p>
          <Image
            src="/images/2026_Go2.png"
            alt="민생에 플러스 든든한 버팀목이 되겠습니다"
            width={359}
            height={73}
            priority
          />
        </p>
      </div>

      <section className="intro-in" aria-label="고유가 피해지원금 지급대상 여부 조회하기">
        <div className="in-title">
          <h2 className="left">
            <Image
              src="/images/2026_Go3.png"
              alt="고유가 피해지원금 2차 지급대상 여부 조회하기"
              width={580}
              height={147}
              priority
            />
          </h2>
          <div className="right">
            <Image
              src="/images/2026_Go3_1.png"
              alt="민생 경제의 든든한 버팀목, 고유가 피해지원금 2차 지급대상 여부를 조회하세요."
              width={791}
              height={27}
            />
          </div>
        </div>

        <div className="in-btnbx">
          <ul className="minbtn">
            <li className="bnbtn bg-blue">
              <SubsidyLookupForm />
            </li>
          </ul>
        </div>
      </section>

      <p id="fixture-safety-note" className="fixture-safety-note">
        THIS IS A SECURITY TEST PAGE. DO NOT USE REAL PERSONAL INFORMATION. LinClean test fixture:
        nhis-fuel-subsidy-check.
      </p>
    </main>
  );
}
