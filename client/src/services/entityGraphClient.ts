import { apiClient } from './apiClient';

export const RELATION_TYPES = ['alias', 'username', 'organization', 'website'] as const;
export type RelationType = (typeof RELATION_TYPES)[number];

export interface EntityRelation {
  id: string;
  candidateId: string;
  relationType: RelationType;
  value: string;
  evidenceId: string | null;
  addedBy: string | null;
  createdAt: string;
}

export async function listEntityRelations(candidateId: string): Promise<EntityRelation[]> {
  const { data } = await apiClient.get<{ items: EntityRelation[] }>(`/v1/candidates/${candidateId}/entity-graph`);
  return data.items;
}

export async function addEntityRelation(
  candidateId: string,
  relationType: RelationType,
  value: string,
): Promise<EntityRelation> {
  const { data } = await apiClient.post<EntityRelation>(`/v1/candidates/${candidateId}/entity-graph`, {
    relationType,
    value,
  });
  return data;
}
