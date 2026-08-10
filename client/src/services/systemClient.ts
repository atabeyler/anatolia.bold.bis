import { apiClient } from './apiClient';

export interface HealthReady {
  status: 'ready' | 'not_ready';
  version: string;
  timestamp: string;
  biometricProvider: string;
  biometricSearch: string;
  uptimeSeconds: number;
  dbPool: { size: number; idle: number };
}

export async function getHealthReady(): Promise<HealthReady> {
  const { data } = await apiClient.get<HealthReady>('/health/ready');
  return data;
}

export interface AuditIntegrityReport {
  eventsChecked: number;
  intact: boolean;
  breaks: string[];
}

export async function verifyAuditIntegrity(): Promise<AuditIntegrityReport> {
  const { data } = await apiClient.get<AuditIntegrityReport>('/v1/audit/integrity');
  return data;
}

export interface BiometricThreshold {
  id: string;
  modelName: string;
  modelVersion: string;
  threshold: number;
  equalErrorRate: number;
  pairCount: number;
  createdAt: string;
}

export async function listBiometricThresholds(): Promise<BiometricThreshold[]> {
  const { data } = await apiClient.get<{ items: BiometricThreshold[] }>(
    '/v1/admin/biometric-thresholds',
  );
  return data.items;
}

export interface ConnectorStatus {
  slot: string;
  providerName: string;
  isMock: boolean;
}

export async function listConnectors(): Promise<ConnectorStatus[]> {
  const { data } = await apiClient.get<{ items: ConnectorStatus[] }>('/v1/admin/connectors');
  return data.items;
}
