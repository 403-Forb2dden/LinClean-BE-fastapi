import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "리다이렉트 체인 테스트 Fixture",
  description: "LinClean URL 언체이너 검증용 리다이렉트 체인 테스트 사이트입니다.",
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
