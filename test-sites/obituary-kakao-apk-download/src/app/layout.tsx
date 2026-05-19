import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "故 홍길동님 부고장 테스트 Fixture",
  description: "Static LinClean fixture cloned from a KakaoBugo sample with a KakaoTalk APK download lure.",
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
