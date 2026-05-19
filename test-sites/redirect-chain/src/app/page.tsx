const routes = [
  {
    path: "/redirect/1",
    description: "0.5초 후 정상 최종 페이지로 한 번 리다이렉트됩니다.",
  },
  {
    path: "/redirect/3",
    description: "각 hop마다 0.5초씩 기다린 뒤 같은 출처 안에서 두 번 더 이동합니다.",
  },
  {
    path: "/redirect/external",
    description: "0.5초 후 외부 테스트 도메인 example.com으로 이동합니다.",
  },
  {
    path: "/redirect/unsafe-scheme",
    description:
      "0.5초 후 Location 헤더에 javascript: 스킴을 반환합니다. 브라우저에서는 보안 정책상 화면 이동이 보이지 않을 수 있습니다.",
  },
  {
    path: "/redirect/max-hop",
    description: "각 hop마다 0.5초씩 기다리는 긴 체인으로 기본 5 hop 제한을 초과합니다.",
  },
  {
    path: "/redirect/to-suspicious",
    description: "0.5초 후 의심 문구가 있는 비활성 최종 페이지로 이동합니다.",
  },
];

export default function Home() {
  return (
    <main className="fixture-page">
      <header className="fixture-header">
        <span className="fixture-kicker">LinClean 테스트 사이트</span>
        <h1>리다이렉트 체인 테스트 사이트</h1>
        <p>
          리다이렉트 추적, 최대 hop 제한, 비허용 스킴 차단, 외부 도메인 이동,
          최종 페이지 분류를 검증하기 위한 고정 테스트 경로입니다.
        </p>
      </header>

      <section aria-labelledby="routes-heading">
        <h2 id="routes-heading">테스트 경로</h2>
        <div className="route-grid">
          {routes.map((route) => (
            <article className="route-card" key={route.path}>
              <code>{route.path}</code>
              <p>{route.description}</p>
              <a href={route.path}>경로 열기</a>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
