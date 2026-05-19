import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NAVER 로그인 테스트 Fixture",
  description: "Static LinClean NAVER impersonation login fixture with disabled authentication.",
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
