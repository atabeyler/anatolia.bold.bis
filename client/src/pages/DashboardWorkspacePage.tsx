import { useEffect, useState } from 'react';

import { CandidateEnrollmentPanel } from '../components/CandidateEnrollmentPanel';
import { useAuth } from '../features/auth/AuthContext';
import { getHealthReady } from '../services/systemClient';
import { DashboardPage } from './DashboardPage';

const MANAGE_CANDIDATE_ROLES = ['OPERATOR', 'SECURITY_ADMIN', 'SYSTEM_ADMIN'];

export function DashboardWorkspacePage() {
  const { user } = useAuth();
  const canManageCandidates = !!user && MANAGE_CANDIDATE_ROLES.includes(user.role);
  const [biometricProvider, setBiometricProvider] = useState<string | null>(null);

  useEffect(() => {
    if (!canManageCandidates) return;
    getHealthReady()
      .then((health) => setBiometricProvider(health.biometricProvider))
      .catch(() => setBiometricProvider(null));
  }, [canManageCandidates]);

  return (
    <>
      <DashboardPage />
      {canManageCandidates && <CandidateEnrollmentPanel biometricProvider={biometricProvider} />}
    </>
  );
}
