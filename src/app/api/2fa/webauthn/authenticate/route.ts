import { generateAuthenticationOptions } from '@simplewebauthn/server';

import { getServerSession, rpID } from '@/app/api/auth/options';
import { prisma } from '@/server/db';

export const GET = async () => {
  const session = await getServerSession();

  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  const existingAuthenticators = await prisma.authenticator.findMany({
    where: {
      userId: session.user.id,
    },
    select: {
      credentialID: true,
    },
  });

  if (!existingAuthenticators?.length) {
    return new Response('Unauthorized', { status: 401 });
  }

  const options = await generateAuthenticationOptions({
    allowCredentials: existingAuthenticators.map(existingAuthenticator => ({
      id: new Uint8Array(existingAuthenticator.credentialID),
      type: 'public-key',
    })),
    userVerification: 'preferred',
    rpID,
  });

  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: {
      currentChallenge: options.challenge,
    },
  });

  return new Response(JSON.stringify(options), { status: 200 });
};
