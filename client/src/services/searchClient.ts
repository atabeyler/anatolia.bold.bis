import { apiClient } from './apiClient';

/**
 * Per-slot outcome of automatic external evidence collection for one search.
 * Web/news enrich known local candidates. Reverse-image discovery can run
 * directly against the sanitized probe when a real provider is configured.
 */
export type ExternalEvidenceSlotStatus =
  | 'completed'
  | 'partial'
  | 'failed'
  | 'mock'
  | 'unavailable'
  | 'not_configured'
  | 'not_run';

export interface ExternalEvidenceStatus {
  web: ExternalEvidenceSlotStatus;
  news: ExternalEvidenceSlotStatus;
  social: ExternalEvidenceSlotStatus;
  reverseImage: ExternalEvidenceSlotStatus;
}

export interface SearchExternalEvidenceDetail {
  key: string;
  params?: Record<string, unknown>;
}

export interface SearchExternalEvidenceItem {
  sourceType: string;
  providerName: string;
  title: string;
  titleKey: string | null;
  titleParams: Record<string, unknown> | null;
  url: string | null;
  snippet: string | null;
  details: SearchExternalEvidenceDetail[];
  confidenceScore: number;
}

export interface SearchSummary {
  id: string;
  caseReference: string;
  purpose: string;
  requestedByName: string;
  status: string;
  latitude: number | null;
  longitude: number | null;
  topK: number | null;
  startedAt: string | null;
  completedAt: string | null;
  failureCode: string | null;
  failureMessageKey: string | null;
  createdAt: string;
  /**
   * `null` until automatic external evidence collection has reported an
   * outcome for this search, or forever when automatic collection is off.
   */
  externalEvidenceStatus: ExternalEvidenceStatus | null;
  /** Search-level evidence discovered directly from the uploaded image. */
  externalEvidence: SearchExternalEvidenceItem[];
}

export interface SearchSummaryPage {
  items: SearchSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface SearchCandidate {
  id: string;
  candidateId: string;
  referenceCode: string;
  fullName: string;
  score: number;
  status: 'pending' | 'confirmed' | 'rejected' | 'inconclusive' | 'needs_second_review';
  reviewedByName: string | null;
  reviewedAt: string | null;
}

export interface CreateSearchResult {
  search: SearchSummary;
  candidates: SearchCandidate[];
  autoOsintEnabled?: boolean;
}

interface CreateSearchApiResponse {
  search: SearchSummary;
  candidates?: SearchCandidate[];
  autoOsintEnabled?: boolean;
}

const SEARCH_STATUS_POLL_INTERVAL_MS = 500;
const SEARCH_STATUS_POLL_TIMEOUT_MS = 300_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeSearchResult(result: CreateSearchApiResponse): CreateSearchResult {
  return {
    ...result,
    candidates: result.candidates ?? [],
  };
}

export async function getSearchStatus(searchId: string): Promise<CreateSearchResult> {
  const { data } = await apiClient.get<CreateSearchApiResponse>(`/v1/search/${searchId}/status`);
  return normalizeSearchResult(data);
}

/**
 * Async search flow: `POST /v1/search/face` returns a queued search row and
 * this helper polls until both biometric processing and, when enabled,
 * automatic external evidence collection have reported their result.
 * `onProgress` receives every server state transition so the UI can expose
 * queued/processing progress instead of appearing frozen during inference.
 */
export async function createSearch(
  caseReference: string,
  purpose: string,
  image: File,
  coords: { latitude: number; longitude: number } | null,
  onProgress?: (result: CreateSearchResult) => void,
): Promise<CreateSearchResult> {
  const form = new FormData();
  form.append('caseReference', caseReference);
  form.append('purpose', purpose);
  form.append('image', image);
  if (coords) {
    form.append('latitude', String(coords.latitude));
    form.append('longitude', String(coords.longitude));
  }
  const { data } = await apiClient.post<CreateSearchApiResponse>('/v1/search/face', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });

  const deadline = Date.now() + SEARCH_STATUS_POLL_TIMEOUT_MS;
  let latest = normalizeSearchResult(data);
  onProgress?.(latest);

  while (
    latest.search.status === 'queued' ||
    latest.search.status === 'processing' ||
    (latest.autoOsintEnabled === true &&
      latest.search.status === 'completed' &&
      latest.search.externalEvidenceStatus === null)
  ) {
    if (Date.now() >= deadline) {
      return latest;
    }
    await sleep(SEARCH_STATUS_POLL_INTERVAL_MS);
    latest = await getSearchStatus(latest.search.id);
    onProgress?.(latest);
  }
  return latest;
}

export async function listSearches(page = 1, pageSize = 50): Promise<SearchSummaryPage> {
  const { data } = await apiClient.get<SearchSummaryPage>('/v1/search', { params: { page, pageSize } });
  return data;
}

export async function getSearchCandidates(searchId: string): Promise<SearchCandidate[]> {
  const { data } = await apiClient.get<SearchCandidate[]>(`/v1/search/${searchId}/candidates`);
  return data;
}

export async function verifyCandidate(candidateId: string, searchId: string): Promise<SearchCandidate> {
  const { data } = await apiClient.post<SearchCandidate>(`/v1/candidates/${candidateId}/verify`, { searchId });
  return data;
}

export async function rejectCandidate(candidateId: string, searchId: string): Promise<SearchCandidate> {
  const { data } = await apiClient.post<SearchCandidate>(`/v1/candidates/${candidateId}/reject`, { searchId });
  return data;
}

export async function markCandidateInconclusive(candidateId: string, searchId: string): Promise<SearchCandidate> {
  const { data } = await apiClient.post<SearchCandidate>(`/v1/candidates/${candidateId}/inconclusive`, { searchId });
  return data;
}
