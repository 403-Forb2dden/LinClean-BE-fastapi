import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "명지대학교 통합로그인 테스트 Fixture",
  description: "Static LinClean fixture clone with disabled authentication behavior.",
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
