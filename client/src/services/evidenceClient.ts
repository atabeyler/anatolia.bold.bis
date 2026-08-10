import { apiClient } from './apiClient';

export interface EvidenceItem {
  id: string;
  candidateId: string;
  sourceType: string;
  providerName: string;
  title: string | null;
  url: string | null;
  snippet: string | null;
  confidenceScore: number | null;
  collectedBy: string | null;
  createdAt: string;
}

export async function listEvidence(candidateId: string): Promise<EvidenceItem[]> {
  const { data } = await apiClient.get<{ items: EvidenceItem[] }>(`/v1/candidates/${candidateId}/evidence`);
  return data.items;
}
