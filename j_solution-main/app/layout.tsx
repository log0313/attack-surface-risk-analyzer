import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css"; // 👈 최상위 폴더에 있는 css를 여기서 불러옵니다!

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Risk Assistant Dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ko">
      <body className={inter.className}>{children}</body>
    </html>
  );
}
