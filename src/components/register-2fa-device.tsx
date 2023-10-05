'use client';

import { startRegistration } from '@simplewebauthn/browser';
import { Session } from 'next-auth';
import { signOut } from 'next-auth/react';

import { Button } from './ui/button';

export const Register2FADevice = ({ session }: { session: Session | null }) => {
  async function handleRegister() {
    if (!session) return;
    const resp = await fetch('/api/2fa/webauthn/register');
    try {
      const data = await resp.json();
      // Pass the options to the authenticator and wait for a response
      const attResp = await startRegistration({ ...data });
      // POST the response to the endpoint that calls
      // @simplewebauthn/server -> verifyRegistrationResponse()
      await fetch('/api/2fa/webauthn/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(attResp),
      });

      await signOut();
    } catch (error) {
      console.error(error);
    }
  }

  return (
    <Button variant="secondary" onClick={handleRegister}>
      Register a 2FA Device
    </Button>
  );
};
