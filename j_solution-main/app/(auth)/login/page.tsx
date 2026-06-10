"use client";

import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    document.cookie = "isLoggedIn=true; path=/;";
    router.push("/");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-base px-4">
      <div className="bg-bg-card p-8 rounded-2xl shadow-2xl max-w-md w-full border border-border">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[#00C7A9]/10 mb-4 border border-[rgba(0,199,169,0.2)] shadow-[0_0_20px_rgba(0,199,169,0.15)]">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-8 h-8 text-accent-blue" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <h1 className="text-2xl font-extrabold text-text-primary tracking-tight">Security Admin</h1>
          <p className="text-text-muted mt-2 text-[13px]">
            대시보드에 접근하려면 로그인하세요.
          </p>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-[0.8px] mb-1.5">
              이메일
            </label>
            <input
              type="email"
              className="w-full placeholder:text-text-muted/50"
              placeholder="admin@example.com"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-[0.8px] mb-1.5">
              비밀번호
            </label>
            <input
              type="password"
              className="w-full placeholder:text-text-muted/50"
              placeholder="••••••••"
              required
            />
          </div>
          <div className="pt-2">
            <button type="submit" className="btn-primary w-full py-2.5 text-[15px]">
              로그인
            </button>
            <button
              type="button"
              onClick={() => router.push("/signup")}
              className="btn-ghost w-full py-2.5 mt-3 text-[14px]"
            >
              회원가입
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
