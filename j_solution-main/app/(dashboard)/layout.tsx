"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

const NAV_ITEMS = [
  { href: "/",        icon: "⬡", label: "Overview" },
  { href: "/assets",  icon: "🔍", label: "Asset Discovery" },
  { href: "/risk",    icon: "⚠", label: "Risk Analysis" },
  { href: "/reports", icon: "✦", label: "AI Reports" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router   = useRouter();

  const handleLogout = () => {
    document.cookie = "isLoggedIn=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC;";
    router.push("/login");
  };

  return (
    <div className="flex h-screen bg-bg-base overflow-hidden">
      {/* === SIDEBAR === */}
      <aside className="w-56 min-w-56 bg-bg-surface border-r border-border flex flex-col">
        {/* Logo */}
        <div className="p-5 pb-4 border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#00C7A9] to-[#00a88e] flex items-center justify-center text-base font-black text-[#0d1117]">
              ⬡
            </div>
            <div>
              <div className="text-[13px] font-bold text-text-primary tracking-wide">
                Security Assistant
              </div>
              <div className="text-[10px] text-text-muted mt-0.5">Risk Management.</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 flex flex-col gap-0.5">
          <div className="text-[10px] font-semibold tracking-wider text-text-muted px-2.5 pt-1.5 pb-1 uppercase">
            Menu
          </div>
          {NAV_ITEMS.map(({ href, icon, label }) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link key={href} href={href} className={`
                flex items-center gap-2.5 px-3 py-2 rounded-lg no-underline text-[13px] transition-all duration-150
                ${active 
                  ? "font-semibold text-text-primary bg-bg-hover border-l-2 border-accent-cyan" 
                  : "font-normal text-text-secondary bg-transparent border-l-2 border-transparent hover:bg-bg-hover hover:text-text-primary"}
              `}>
                <span className="text-[15px]">{icon}</span>
                {label}
              </Link>
            );
          })}
        </nav>

        {/* Bottom / Status */}
        <div className="p-3 border-t border-border">
          {/* Scan status pill */}
          <div className="bg-[rgba(82,196,26,0.08)] border border-[rgba(82,196,26,0.2)] rounded-lg py-2 px-3 flex items-center gap-2 mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-risk-low shadow-[0_0_0_2px_rgba(82,196,26,0.3)] animate-[pulse-glow_2s_infinite]" />
            <span className="text-[11px] text-text-secondary">Scanner Online</span>
          </div>

          <button 
            onClick={handleLogout} 
            className="w-full p-2 bg-transparent border border-border rounded-lg text-text-muted text-xs cursor-pointer transition-colors duration-150 hover:text-risk-critical hover:border-[rgba(255,77,79,0.4)]"
          >
            로그아웃
          </button>
        </div>
      </aside>

      {/* === MAIN === */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-14 min-h-14 bg-bg-surface border-b border-border flex items-center justify-between px-6">
          <div className="text-[13px] text-text-muted">
            Last scan: <span className="text-text-secondary">2026-03-27 18:30 KST</span>
          </div>
          <div className="flex items-center gap-2.5">
            <div className="px-3 py-1 bg-[rgba(255,77,79,0.1)] border border-[rgba(255,77,79,0.25)] rounded-full text-xs text-risk-critical font-semibold animate-[pulse-glow_2.5s_infinite]">
              ● 8 Critical
            </div>
            <div className="w-7.5 h-7.5 rounded-full bg-gradient-to-br from-[#00C7A9] to-[#00a88e] flex items-center justify-center text-xs font-bold text-white">
              A
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-5">
          {children}
        </div>
      </main>
    </div>
  );
}
