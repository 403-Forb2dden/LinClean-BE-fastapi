import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "고유가 피해지원금 대상 여부 조회 테스트 Fixture",
  description: "Static LinClean fixture clone with disabled PII submission behavior.",
  robots: {
    index: false,
    follow: false,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
