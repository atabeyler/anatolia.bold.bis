import { apiClient } from './apiClient';

export interface AuditEvent {
  id: string;
  timestamp: string;
  actorUserId: string | null;
  actorUserCode: string | null;
  actorRole: string | null;
  action: string;
  requestId: string;
  caseReference: string | null;
  resourceType: string | null;
  resourceId: string | null;
  result: string;
  source: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: unknown;
  organizationId: string | null;
  organizationUnitId: string | null;
}

export interface AuditEventPage {
  items: AuditEvent[];
  page: number;
  pageSize: number;
  total: number;
}

export interface AuditEventFilters {
  dateFrom?: string;
  dateTo?: string;
  actor?: string;
  action?: string;
  caseReference?: string;
  resourceType?: string;
  result?: string;
  page?: number;
  pageSize?: number;
}

export async function listAuditEvents(filters: AuditEventFilters): Promise<AuditEventPage> {
  const { data } = await apiClient.get<AuditEventPage>('/v1/audit', { params: filters });
  return data;
}
