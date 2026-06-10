import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export default function proxy(request: NextRequest) {
  // 1. 브라우저 쿠키에 'isLoggedIn' 이라는 방문증(토큰)이 있는지 확인합니다.
  const isLoggedIn = request.cookies.get("isLoggedIn");

  // 2. 방문증이 없는데 메인 화면('/')에 들어가려고 하면?
  if (!isLoggedIn && request.nextUrl.pathname === "/") {
    // 로그인 페이지('/login')로 방향을 강제로 틀어버립니다!
    return NextResponse.redirect(new URL("/login", request.url));
  }

  // 3. 이미 로그인 창('/login')에 있는데 방문증이 있다면? (로그인 상태)
  if (isLoggedIn && request.nextUrl.pathname === "/login") {
    // 굳이 로그인할 필요 없으니 대시보드('/')로 보냅니다.
    return NextResponse.redirect(new URL("/", request.url));
  }

  // 문제가 없으면 원래 가려던 길을 그대로 통과시킵니다.
  return NextResponse.next();
}

// 이 문지기(미들웨어)가 검사할 주소들을 설정합니다.
export const config = {
  // 메인 화면('/')과 로그인 화면('/login')으로 갈 때만 작동하게 합니다.
  matcher: ["/", "/login"],
};
