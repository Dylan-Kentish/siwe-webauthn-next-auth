import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';

import { rpID, expectedOrigin, rpName, getServerSession } from '@/app/api/auth/options';
import { prisma } from '@/server/db';

export const GET = async () => {
  const session = await getServerSession();

  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  const userAuthenticators = await prisma.authenticator.findMany({
    where: {
      userId: session.user.id,
    },
  });

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: session.user.id,
    userName: session.user.id,
    // Don't prompt users for additional information about the authenticator
    // (Recommended for smoother UX)
    attestationType: 'none',
    // Prevent users from re-registering existing authenticators
    excludeCredentials: userAuthenticators.map(authenticator => ({
      id: authenticator.credentialID,
      type: 'public-key',
    })),
    authenticatorSelection: {
      // "Discoverable credentials" used to be called "resident keys". The
      // old name persists in the options passed to `navigator.credentials.create()`.
      residentKey: 'required',
      userVerification: 'preferred',
    },
  });

  // Remember the challenge for this user
  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: {
      currentChallenge: options.challenge,
    },
  });

  return new Response(JSON.stringify(options), {
    headers: {
      'Content-Type': 'application/json',
    },
  });
};

export const POST = async (request: Request) => {
  const session = await getServerSession();

  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  const userId = session.user.id;

  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: {
      id: true,
      role: true,
      is2FAEnabled: true,
      currentChallenge: true,
    },
  });

  if (!user) {
    return new Response('Unauthorized', { status: 401 });
  }

  const response = await request.json();
  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    if (expectedChallenge)
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  if (!verification) {
    return new Response('Unauthorized', { status: 401 });
  }
  const { verified, registrationInfo } = verification;
  const { credentialPublicKey, credentialID, counter, credentialBackedUp, credentialDeviceType } =
    registrationInfo || {};

  if (!credentialID || !credentialPublicKey) {
    return new Response('Unauthorized', { status: 401 });
  }

  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: {
      is2FAEnabled: true,
      Authenticator: {
        create: {
          // base64 encode
          credentialID: Buffer.from(credentialID),
          credentialPublicKey: Buffer.from(credentialPublicKey),
          counter: counter ?? 0,
          credentialBackedUp: credentialBackedUp ?? false,
          credentialDeviceType: credentialDeviceType ?? 'singleDevice',
        },
      },
    },
  });

  return new Response(JSON.stringify({ verified }), {
    headers: {
      'Content-Type': 'application/json',
    },
  });
};
