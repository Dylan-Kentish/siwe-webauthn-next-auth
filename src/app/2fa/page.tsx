import { NextPage } from 'next';
import { notFound } from 'next/navigation';

import { Register2FADevice } from '@/components/register-2fa-device';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Verify2FA } from '@/components/verify-2fa';
import { prisma } from '@/server/db';

import { getServerSession } from '../api/auth/options';

const Page: NextPage = async () => {
  const session = await getServerSession();

  if (!session) {
    return notFound();
  }

  const authenticators = await prisma.authenticator.findMany({
    where: {
      userId: session.user.id,
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>2FA</CardTitle>
        <CardDescription>
          Add additional security to your account with two-factor authentication.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {session ? (
          <>
            <p>
              You currently have 2FA{' '}
              <strong>{session.user.is2FAEnabled ? 'enabled' : 'disabled'}</strong>.
            </p>
            <p>
              This session is <strong>{session.is2FAVerified ? 'verified' : 'not verified'}</strong>
              .
            </p>
          </>
        ) : (
          <p>
            You are currently <strong>not signed in</strong>.
          </p>
        )}
      </CardContent>
      <CardContent>
        <p>Authenticators:</p>
        <ul>
          {authenticators.map(authenticator => (
            <li key={authenticator.id}>{authenticator.credentialDeviceType}</li>
          ))}
        </ul>
      </CardContent>
      <CardFooter className="justify-end gap-5">
        <Verify2FA session={session} />
        <Register2FADevice session={session} />
      </CardFooter>
    </Card>
  );
};

export default Page;
