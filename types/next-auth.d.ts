// eslint-disable-next-line @typescript-eslint/no-unused-vars
import NextAuth from 'next-auth';

type Role = 'ADMIN' | 'USER';

declare module 'next-auth' {
  interface AdapterUser {
    id: string;
  }

  interface User {
    id: string;
    role: Role;
    is2FAEnabled?: boolean;
    currentChallenge: string | null;
  }

  interface Session {
    user: User;
    is2FAVerified?: boolean;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    id: string;
    role: Role;
    iat: number;
    exp: number;
    is2FAEnabled?: boolean;
    is2FAVerified?: boolean;
  }
}
