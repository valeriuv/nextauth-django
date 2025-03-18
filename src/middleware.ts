import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { auth } from "./auth";

const protectedRoutes = [
  "/user-info",
  "/dashboard"
];

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};

export default async function middleware(req: NextRequest) {
  try {
    console.log("Middleware - Request path:", req.nextUrl.pathname);
    console.log("Middleware - Checking session...");
    
    // Check for session token cookie
    const sessionToken = req.cookies.get('__Secure-next-auth.session-token');
    console.log("Middleware - Session token cookie:", {
      exists: !!sessionToken,
      value: sessionToken?.value ? 'present' : 'missing'
    });
    
    const session = await auth();
    console.log("Middleware - Session check result:", {
      hasSession: !!session,
      sessionKeys: session ? Object.keys(session) : [],
      userEmail: session?.user?.email,
      hasAccessToken: !!session?.accessToken
    });
    
    const { pathname } = req.nextUrl;
    const isProtectedRoute = protectedRoutes.some((route) =>
      pathname.startsWith(route)
    );
    
    console.log("Middleware - Route check:", {
      pathname,
      isProtectedRoute,
      protectedRoutes
    });

    if (isProtectedRoute && !session) {
      console.log("Middleware - Redirecting to signin: Protected route without session");
      const signInUrl = new URL("/auth/signin", req.url);
      signInUrl.searchParams.set("callbackUrl", pathname);
      return NextResponse.redirect(signInUrl);
    }

    console.log("Middleware - Allowing request to proceed");
    return NextResponse.next();
  } catch (error) {
    console.error("Middleware error:", error);
    // In case of error, we'll allow the request to proceed but log the error
    return NextResponse.next();
  }
}