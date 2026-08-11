import { apiClient } from './apiClient';

export interface CandidateRecord {
  id: string;
  referenceCode: string;
  fullName: string;
  notes: string | null;
}

export interface BiometricTemplate {
  id: string;
  candidateId: string;
  modelName: string;
  modelVersion: string;
  embeddingDimension: number;
  qualityScore: number;
  sourceReference: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface PossibleDuplicate {
  candidateId: string;
  similarity: number;
}

export interface EnrollmentResult extends BiometricTemplate {
  possibleDuplicates: PossibleDuplicate[];
}

export async function createCandidate(
  referenceCode: string,
  fullName: string,
  notes: string,
): Promise<CandidateRecord> {
  const { data } = await apiClient.post<CandidateRecord>('/v1/candidates', {
    referenceCode,
    fullName,
    notes: notes || undefined,
  });
  return data;
}

export async function enrollReferencePhoto(candidateId: string, image: File): Promise<EnrollmentResult> {
  const form = new FormData();
  form.append('image', image);
  const { data } = await apiClient.post<EnrollmentResult>(
    `/v1/candidates/${candidateId}/reference-photos`,
    form,
    { headers: { 'Content-Type': 'multipart/form-data' } },
  );
  return { ...data, possibleDuplicates: data.possibleDuplicates ?? [] };
}

export async function listTemplates(candidateId: string): Promise<BiometricTemplate[]> {
  const { data } = await apiClient.get<{ items: BiometricTemplate[] }>(
    `/v1/candidates/${candidateId}/templates`,
  );
  return data.items;
}

export async function revokeTemplate(candidateId: string, templateId: string): Promise<void> {
  await apiClient.post(`/v1/candidates/${candidateId}/templates/${templateId}/revoke`);
}
