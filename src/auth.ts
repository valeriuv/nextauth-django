import Credentials from "next-auth/providers/credentials";
import Google from "next-auth/providers/google";
import Facebook from "next-auth/providers/facebook";
import NextAuth from "next-auth";
import { User } from "next-auth";
import { env } from "./env";

interface TokenUser extends User {
  id: string;
  email: string;
  name: string;
  image?: string;
  emailVerified: Date | null;
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
            accessToken: data.access_token,
          };
          console.log("Created user object:", { 
            id: user.id,
            email: user.email,
            hasAccessToken: !!user.accessToken 
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
  },
  jwt: {
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async jwt({ token, account, user }) {
      try {
        console.log("JWT callback called with:", { 
          hasAccount: !!account, 
          hasUser: !!user,
          accountProvider: account?.provider,
          userEmail: user?.email,
          existingToken: !!token,
          tokenKeys: token ? Object.keys(token) : [],
          tokenUser: token?.user ? Object.keys(token.user) : [],
          tokenAccessToken: !!token?.accessToken
        });

        // If we have an existing token with user data, return it
        if (token.user) {
          console.log("Using existing token with user data:", {
            userId: (token.user as TokenUser).id,
            userEmail: (token.user as TokenUser).email,
            hasAccessToken: !!token.accessToken
          });
          return token;
        }

        // Handle social login (Google, Facebook)
        if (account && user && account.provider && account.provider !== 'credentials') {
          console.log("Making social auth request to backend with:", {
            provider: account.provider,
            hasAccessToken: !!account.access_token,
            hasRefreshToken: !!account.refresh_token,
            userId: user.id,
            userEmail: user.email
          });
          
          if (!account.access_token) {
            throw new Error("Missing access token for social login");
          }

          const res = await fetch("http://localhost:8000/api/auth/social/", {
            method: "POST",
            body: JSON.stringify({
              provider: account.provider,
              access_token: account.access_token
            }),
            headers: {
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
          });

          const data = await res.json();
          console.log("Social auth response:", { 
            status: res.status, 
            hasData: !!data,
            hasAccessToken: !!data.access_token,
            error: data.error,
            data: data
          });

          if (!res.ok) {
            console.error("Social auth error response:", data);
            throw new Error(data.error || "Social authentication failed");
          }

          const newToken = {
            ...token,
            accessToken: data.access_token,
            refreshToken: account.refresh_token,
            user: {
              ...user,
              id: user.id || user.email || '',
              email: user.email || '',
              name: user.name || '',
              image: user.image || '',
              emailVerified: null,
            },
          };
          console.log("Created new token with:", {
            hasAccessToken: !!newToken.accessToken,
            hasRefreshToken: !!newToken.refreshToken,
            hasUser: !!newToken.user,
            userId: newToken.user.id,
            userEmail: newToken.user.email
          });
          return newToken;
        }

        // Handle credentials login
        if (user && user.accessToken) {
          console.log("Processing credentials login in JWT callback with:", {
            userId: user.id,
            userEmail: user.email,
            hasAccessToken: !!user.accessToken
          });
          return {
            ...token,
            accessToken: user.accessToken,
            user: {
              ...user,
              id: user.id || user.email || '',
              email: user.email || '',
              name: user.name || '',
              image: user.image || '',
              emailVerified: null,
            },
          }
        }

        return token;
      } catch (error) {
        console.error("JWT callback error:", error);
        throw error;
      }
    },
    async session({ session, token }) {
      try {
        console.log("Session callback called with:", { 
          hasToken: !!token,
          hasUser: !!token.user,
          userEmail: (token.user as TokenUser)?.email,
          tokenKeys: token ? Object.keys(token) : [],
          tokenUser: token?.user ? Object.keys(token.user) : [],
          hasAccessToken: !!token.accessToken
        });
        
        session.accessToken = token.accessToken as string;
        session.user = (token.user as TokenUser) || {
          id: '',
          email: '',
          name: '',
          image: '',
          emailVerified: null,
        };
        
        console.log("Created session with:", {
          hasAccessToken: !!session.accessToken,
          hasUser: !!session.user,
          userId: session.user.id,
          userEmail: session.user.email
        });
        
        return session;
      } catch (error) {
        console.error("Session callback error:", error);
        throw error;
      }
    },
  },
  debug: true,
  trustHost: true,
  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: true
      }
    }
  }
});

