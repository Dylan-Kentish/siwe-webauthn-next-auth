'use client';

import { startAuthentication } from '@simplewebauthn/browser';
import { Session } from 'next-auth';
import { signIn } from 'next-auth/react';

import { Button } from './ui/button';

export const Verify2FA = ({ session }: { session: Session | null }) => {
  const verifying = session?.user.is2FAEnabled && !session?.is2FAVerified;

  async function handleVerify() {
    if (!session?.user.is2FAEnabled) return;
    const resp = await fetch('/api/2fa/webauthn/authenticate');
    const data = await resp.json();
    if (verifying) {
      try {
        // Pass the options to the authenticator and wait for a response
        const asseResp = await startAuthentication(data);
        await signIn('webauthn', {
          verification: JSON.stringify(asseResp),
        });
      } catch (error) {
        console.error(error);
      }
    }
  }

  return (
    <Button variant="secondary" onClick={handleVerify}>
      Verify 2FA
    </Button>
  );
};
