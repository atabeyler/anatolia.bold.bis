import { apiClient } from './apiClient';

export interface Organization {
  id: string;
  name: string;
  createdAt: string;
}

export interface OrganizationUnit {
  id: string;
  organizationId: string;
  parentUnitId: string | null;
  name: string;
  createdAt: string;
}

export async function listOrganizations(): Promise<Organization[]> {
  const { data } = await apiClient.get<Organization[]>('/v1/admin/organizations');
  return data;
}

export async function createOrganization(name: string): Promise<Organization> {
  const { data } = await apiClient.post<Organization>('/v1/admin/organizations', { name });
  return data;
}

export async function listUnits(organizationId: string): Promise<OrganizationUnit[]> {
  const { data } = await apiClient.get<OrganizationUnit[]>(
    `/v1/admin/organizations/${organizationId}/units`,
  );
  return data;
}

export async function createUnit(
  organizationId: string,
  name: string,
  parentUnitId?: string,
): Promise<OrganizationUnit> {
  const { data } = await apiClient.post<OrganizationUnit>(
    `/v1/admin/organizations/${organizationId}/units`,
    { name, parentUnitId },
  );
  return data;
}

export async function assignMembership(
  userId: string,
  organizationId: string,
  organizationUnitId?: string,
): Promise<void> {
  await apiClient.post('/v1/admin/memberships', {
    userId,
    organizationId,
    organizationUnitId,
  });
}

export async function removeMembership(userId: string, organizationId: string): Promise<void> {
  await apiClient.delete('/v1/admin/memberships', { data: { userId, organizationId } });
}
