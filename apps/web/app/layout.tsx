import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI Website Doctor",
  description: "Local-first website availability monitoring and diagnostics.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
