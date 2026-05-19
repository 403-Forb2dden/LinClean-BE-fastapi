export default function SuspiciousFinalPage() {
  return (
    <main className="fixture-page">
      <section className="final-panel suspicious">
        <span className="fixture-kicker">최종 목적지</span>
        <h1>결제 수단 등록이 필요합니다</h1>
        <p>
          세션이 곧 만료됩니다. 계속 이용하려면 등록을 진행하세요.
        </p>

        <form className="payment-check-form" aria-label="비활성 카드 인증 테스트 폼">
          <div className="form-grid">
            <label>
              <span>카드번호</span>
              <input
                id="test-card-number"
                inputMode="numeric"
                placeholder="카드번호 16자리"
                readOnly
                autoComplete="off"
                data-test-signal="card-number"
              />
            </label>
            <label>
              <span>CVC</span>
              <input
                id="test-card-cvc"
                inputMode="numeric"
                placeholder="CVC 3자리"
                readOnly
                autoComplete="off"
                data-test-signal="card-cvc"
              />
            </label>
            <label>
              <span>만료일</span>
              <input
                id="test-card-expiry"
                inputMode="numeric"
                placeholder="MM/YY"
                readOnly
                autoComplete="off"
                data-test-signal="card-expiry"
              />
            </label>
            <label>
              <span>카드 비밀번호 앞 2자리</span>
              <input
                id="test-card-password-prefix"
                type="password"
                inputMode="numeric"
                maxLength={2}
                placeholder="앞 2자리"
                readOnly
                autoComplete="off"
                data-test-signal="card-password-prefix"
              />
            </label>
          </div>
          <button type="button">
            제출
          </button>
        </form>
      </section>
    </main>
  );
}
