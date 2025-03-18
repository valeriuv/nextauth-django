import Credentials from "next-auth/providers/credentials";
import Google from "next-auth/providers/google";
import Facebook from "next-auth/providers/facebook";
import { User } from "next-auth";
import { env } from "./env";
import NextAuth from "next-auth";

////////////////////////////////////////////////////////////
// Auth flow
////////////////////////////////////////////////////////////  

// User enters email/password
// handleCredentialsSubmit() in signin/page.tsx
// NextAuth calls authorize() in auth.ts
// authorize() makes POST to Django /api/auth/login/
// Django validates credentials and returns access_token
// authorize() creates user object with access_token
// NextAuth calls jwt() callback
// jwt() creates token with user data and access_token
// NextAuth calls session() callback
// session() creates session with user data and access_token
// User is redirected to /dashboard


// social flow
// User clicks social provider button
// handleSocialSignIn() in signin/page.tsx
// NextAuth initiates OAuth flow with provider
// User authenticates with provider (Google/Facebook)
// Provider redirects back with auth code
// NextAuth exchanges code for tokens
// NextAuth calls profile() callback
// profile() creates user object with provider data
// NextAuth calls jwt() callback
// jwt() makes POST to Django /api/auth/social/
// Django validates provider token and returns access_token
// jwt() creates token with user data and access_token
// NextAuth calls session() callback
// session() creates session with user data and access_token
// User is redirected to /dashboard (with #_=_ for Facebook)



interface TokenUser extends User {
  id: string;
  email: string;
  name: string;
  image?: string;
  emailVerified: Date | null;
  accessToken?: string;
  refreshToken?: string;
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Credentials({
      name: "Credentials",
      credentials: { 
        email: { label: "Email", type: "email" }, 
        password: { label: "Password", type: "password" } 
      },
      async authorize(credentials) {
        try {
          console.log("Credentials authorize called with:", { 
            email: credentials?.email,
            hasPassword: !!credentials?.password 
          });
          
          if (!credentials?.email || !credentials?.password) {
            console.log("Missing credentials");
            return null;
          }
          
          console.log("Making request to Django login endpoint");
          const res = await fetch("http://localhost:8000/api/auth/login/", {
            method: "POST",
            body: JSON.stringify({
              email: credentials.email,
              password: credentials.password,
            }),
            headers: { 
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
          });

          console.log("Django login response status:", res.status);
          const data = await res.json();
          console.log("Django login response data:", data);
          
          if (!res.ok) {
            console.error("Login failed:", data.error || "Authentication failed");
            throw new Error(data.error || "Authentication failed");
          }

          const email = credentials.email as string;
          const user = {
            id: email,
            email: email,
            name: email.split('@')[0],
            image: null,
            emailVerified: null,
            accessToken: data.access_token,
          };
          console.log("Created user object:", { 
            id: user.id,
            email: user.email,
            name: user.name,
            hasAccessToken: !!user.accessToken,
            user: user // Log full user object
          });
          
          return user;
        } catch (error) {
          console.error("Credentials auth error:", error);
          return null;
        }
      },
    }),
    Google({
      clientId: env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!,
      clientSecret: env.GOOGLE_CLIENT_SECRET!,
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          response_type: "code",
          scope: "openid email profile"
        }
      },
      async profile(profile) {
        try {
          console.log("Google profile callback received:", profile);
          if (!profile.email) {
            console.error("No email in Google profile");
            throw new Error("No email in Google profile");
          }
          return {
            id: profile.sub,
            email: profile.email,
            name: profile.name,
            image: profile.picture,
            emailVerified: profile.email_verified ? new Date() : null,
            accessToken: profile.access_token,
            refreshToken: profile.refresh_token
          };
        } catch (error) {
          console.error("Google profile error:", error);
          throw error;
        }
      }
    }),
    Facebook({
      clientId: env.NEXT_PUBLIC_FACEBOOK_CLIENT_ID!,
      clientSecret: env.FACEBOOK_CLIENT_SECRET!,
      profile(profile) {
        try {
          console.log("Facebook profile callback received:", profile);
          return {
            id: profile.id,
            email: profile.email,
            name: profile.name,
            image: profile.picture?.data?.url,
            emailVerified: null,
          };
        } catch (error) {
          console.error("Facebook profile error:", error);
          throw error;
        }
      },
    }),
  ],
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
  secret: env.NEXTAUTH_SECRET,
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
    updateAge: 24 * 60 * 60, // 24 hours
  },
  jwt: {
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async jwt({ token, user, account }) {
      console.log("JWT Callback - Input:", { token, user, account });
      
      if (account && user) {
        console.log("JWT Callback - Creating new token for:", user.email);
        const newToken = {
          ...token,
          accessToken: user.accessToken || account.access_token,
          refreshToken: user.refreshToken || account.refresh_token,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            image: user.image,
            emailVerified: (user as TokenUser).emailVerified,
          }
        };
        console.log("JWT Callback - New token created:", newToken);
        return newToken;
      }
      
      console.log("JWT Callback - Returning existing token");
      return token;
    },
    async session({ session, token }) {
      console.log("Session Callback - Input:", { 
        hasSession: !!session,
        hasToken: !!token,
        tokenKeys: token ? Object.keys(token) : [],
        sessionKeys: session ? Object.keys(session) : []
      });
      
      if (token) {
        console.log("Session Callback - Creating new session with token data");
        const tokenUser = token.user as TokenUser;
        console.log("Session Callback - Token user data:", tokenUser);
        
        const newSession = {
          ...session,
          expires: session.expires,
          accessToken: token.accessToken as string | undefined,
          refreshToken: token.refreshToken as string | undefined,
          user: {
            ...session.user,
            id: tokenUser?.id,
            email: tokenUser?.email,
            name: tokenUser?.name,
            image: tokenUser?.image,
            emailVerified: tokenUser?.emailVerified,
          }
        };
        console.log("Session Callback - New session created:", {
          hasAccessToken: !!newSession.accessToken,
          hasUser: !!newSession.user,
          userEmail: newSession.user?.email
        });
        return newSession;
      }
      
      console.log("Session Callback - No token found, returning default session");
      return session;
    }
  },
  debug: true,
  trustHost: true,
  cookies: {
    sessionToken: {
      name: `authjs.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production'
      }
    }
  }
});

