import React from 'react';

import { Session } from 'next-auth';

import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

export const SessionInfo: React.FC<{ session: Session }> = ({ session }) => {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Session Info</CardTitle>
      </CardHeader>
      <CardContent>
        <p>Session:</p>
        <p>
          This session is <strong>{session.is2FAVerified ? 'verified' : 'not verified'}</strong>.
        </p>
      </CardContent>
      <CardContent>
        <p>User:</p>
        <p className="truncate">ID: {session.user.id}</p>
        <p>
          Role: <strong>{session.user.role}</strong>
        </p>
        <p>
          2FA Enabled: <strong>{session.user.is2FAEnabled ? 'TRUE' : 'FALSE'}</strong>
        </p>
      </CardContent>
    </Card>
  );
};
