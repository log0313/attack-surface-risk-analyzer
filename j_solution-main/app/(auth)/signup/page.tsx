"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function SignupPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  const handleSignup = (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== passwordConfirm) {
      setErrorMessage("비밀번호가 일치하지 않습니다.");
      return;
    }
    setErrorMessage("");
    router.push("/login");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-base px-4 py-12">
      <div className="bg-bg-card p-8 rounded-2xl shadow-2xl max-w-md w-full border border-border">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-[#00C7A9]/10 mb-4 border border-[rgba(0,199,169,0.2)] shadow-[0_0_15px_rgba(0,199,169,0.15)] text-accent-blue">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-7 h-7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
          </div>
          <h1 className="text-2xl font-extrabold text-text-primary tracking-tight">계정 생성</h1>
          <p className="text-text-muted mt-2 text-[13px]">
            Security Admin의 관리자 계정을 생성합니다.
          </p>
        </div>

        <form onSubmit={handleSignup} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-[0.8px] mb-1.5">
              이름
            </label>
            <input
              type="text"
              className="w-full placeholder:text-text-muted/50"
              placeholder="홍길동"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-[0.8px] mb-1.5">
              이메일
            </label>
            <input
              type="email"
              className="w-full placeholder:text-text-muted/50"
              placeholder="admin@example.com"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
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
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-text-secondary uppercase tracking-[0.8px] mb-1.5">
              비밀번호 확인
            </label>
            <input
              type="password"
              className="w-full placeholder:text-text-muted/50"
              placeholder="••••••••"
              required
              value={passwordConfirm}
              onChange={(e) => setPasswordConfirm(e.target.value)}
            />
          </div>
          
          <div className="pt-4">
            <button type="submit" className="btn-primary w-full py-2.5 text-[15px]">
              회원가입 완료
            </button>
            <button
              type="button"
              onClick={() => router.push("/login")}
              className="btn-ghost w-full py-2.5 mt-3 text-[14px]"
            >
              돌아가기
            </button>
          </div>

          {errorMessage && (
            <div className="mt-4 p-3 bg-[rgba(255,77,79,0.1)] border border-[rgba(255,77,79,0.3)] rounded-lg text-center">
              <p className="text-risk-critical text-xs font-semibold">{errorMessage}</p>
            </div>
          )}
        </form>
      </div>
    </div>
  );
}