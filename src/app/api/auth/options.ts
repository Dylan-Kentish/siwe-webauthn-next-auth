import 'server-only';

import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { type NextAuthOptions, getServerSession as getServerSessionInternal } from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { getCsrfToken } from 'next-auth/react';
import { SiweMessage } from 'siwe';

import { env } from '@/env.mjs';
import { toBase64 } from '@/lib/convert';
import { prisma } from '@/server/db';

export const rpName = 'SIWE + WEBAUTHN + NEXT-AUTH';
export const rpID = env.VERIFIED_DOMAIN;
export const domain = process.env.NODE_ENV === 'production' ? rpID : `${rpID}:3000`;
export const origin = process.env.NODE_ENV === 'production' ? `https://${rpID}` : `http://${rpID}`;
export const expectedOrigin = process.env.NODE_ENV === 'production' ? origin : `${origin}:3000`;

export const authOptions: NextAuthOptions = {
  session: {
    strategy: 'jwt',
  },
  providers: [
    Credentials({
      id: 'siwe',
      name: 'siwe',
      credentials: {
        message: {
          label: 'Message',
          type: 'text',
          placeholder: '0x0',
        },
        signature: {
          label: 'Signature',
          type: 'text',
          placeholder: '0x0',
        },
      },
      async authorize(credentials, req) {
        if (!env.VERIFIED_DOMAIN) return null;

        try {
          const siwe = new SiweMessage(JSON.parse(credentials?.message || '{}'));

          const nonce = await getCsrfToken({ req: { headers: req.headers } });

          const result = await siwe.verify({
            signature: credentials?.signature || '',
            domain,
            nonce,
          });

          if (result.success) {
            const dbUser = await prisma.user.upsert({
              where: {
                id: siwe.address,
              },
              update: {},
              create: {
                id: siwe.address,
              },
              select: {
                id: true,
                role: true,
                is2FAEnabled: true,
              },
            });

            return {
              id: siwe.address,
              role: dbUser.role,
              is2FAEnabled: dbUser.is2FAEnabled,
              currentChallenge: '',
            };
          } else {
            return null;
          }
        } catch (e) {
          console.error(e);
          return null;
        }
      },
    }),
    Credentials({
      id: 'webauthn',
      name: 'WebAuthn',
      credentials: {},
      async authorize(_, request) {
        if (!env.VERIFIED_DOMAIN) return null;

        const session = await getServerSession();

        if (!session) {
          return null;
        }

        const userId = session.user.id;

        if (!userId) return null;

        const user = await prisma.user.findUnique({
          where: {
            id: userId,
          },
          select: {
            id: true,
            role: true,
            is2FAEnabled: true,
            currentChallenge: true,
            Authenticator: true,
          },
        });

        if (!user) {
          return null;
        }

        const expectedChallenge = user.currentChallenge;

        const authenticationResponse = JSON.parse(request.body?.verification);

        if (!user.Authenticator.length) return null;

        const authenticator = user.Authenticator.find(
          authenticator => toBase64(authenticator.credentialID) === authenticationResponse.id
        );
        if (!authenticator) {
          throw new Error(
            `Could not find authenticator ${authenticationResponse.id} for user ${user.id}`
          );
        }

        if (!authenticator || !expectedChallenge) {
          throw new Error(
            `Could not find authenticator ${authenticationResponse.id} for user ${user.id}`
          );
        }

        let verification;
        try {
          verification = await verifyAuthenticationResponse({
            response: authenticationResponse,
            expectedChallenge,
            expectedOrigin,
            expectedRPID: rpID,
            authenticator: {
              credentialID: new Uint8Array(authenticator.credentialID),
              credentialPublicKey: new Uint8Array(authenticator.credentialPublicKey),
              counter: authenticator.counter,
            },
          });
        } catch (error) {
          console.error(error);
          return null;
        }

        const { verified } = verification || {};

        if (verified) {
          const updatedUser = {
            ...user,
            currentChallenge: null,
          };

          await prisma.user.update({
            where: {
              id: session.user.id,
            },
            data: {
              currentChallenge: null,
            },
          });

          return updatedUser;
        }
        return null;
      },
    }),
  ],
  callbacks: {
    jwt: async ({ token, user }) => {
      if (user) {
        token.id = user.id;
        token.role = user.role;
        token.is2FAEnabled = user.is2FAEnabled;
        token.is2FAVerified = user.is2FAEnabled && user.currentChallenge === null;
      }

      return token;
    },
    session({ session, token }) {
      session.is2FAVerified = token.is2FAVerified as boolean;
      session.user.id = token.id;
      session.user.role = token.role;
      session.user.is2FAEnabled = token.is2FAEnabled;
      return session;
    },
  },
  pages: {
    signIn: '/siwe',
  },
};

export async function getServerSession() {
  const session = await getServerSessionInternal(authOptions);

  return session;
}
