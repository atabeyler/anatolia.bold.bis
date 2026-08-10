import { apiClient } from './apiClient';

export interface PossibleDuplicate {
  candidateId: string;
  referenceCode: string;
  fullName: string;
  nameSimilarity: number;
  sharedEvidenceUrls: string[];
  matchedSignals: string[];
}

export async function listPossibleDuplicates(candidateId: string): Promise<PossibleDuplicate[]> {
  const { data } = await apiClient.get<{ items: PossibleDuplicate[] }>(
    `/v1/candidates/${candidateId}/possible-duplicates`,
  );
  return data.items;
}
