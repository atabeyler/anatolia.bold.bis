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

export interface CollectEvidenceResult {
  items: EvidenceItem[];
  providerErrors: Array<{ provider: string; error: string }>;
}

export async function collectEvidence(candidateId: string, query: string): Promise<CollectEvidenceResult> {
  const { data } = await apiClient.post<CollectEvidenceResult>(
    `/v1/candidates/${candidateId}/evidence/collect`,
    { query },
  );
  return data;
}
