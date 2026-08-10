import { apiClient } from './apiClient';

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
}

const SEARCH_STATUS_POLL_INTERVAL_MS = 500;
const SEARCH_STATUS_POLL_TIMEOUT_MS = 60_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function getSearchStatus(searchId: string): Promise<CreateSearchResult> {
  const { data } = await apiClient.get<CreateSearchResult>(`/v1/search/${searchId}/status`);
  return data;
}

/**
 * Async search flow (madde 18-19): `POST /v1/search/face` is accepted
 * (`202`) immediately with a `queued` search row — the biometric pipeline
 * runs server-side in a background task. This polls
 * `GET /v1/search/{id}/status` until it leaves `queued`/`processing`, so
 * callers keep the same "await a finished result" shape they had before
 * the response contract changed, without needing their own polling loop.
 */
export async function createSearch(
  caseReference: string,
  purpose: string,
  image: File,
  coords: { latitude: number; longitude: number } | null,
): Promise<CreateSearchResult> {
  const form = new FormData();
  form.append('caseReference', caseReference);
  form.append('purpose', purpose);
  form.append('image', image);
  if (coords) {
    form.append('latitude', String(coords.latitude));
    form.append('longitude', String(coords.longitude));
  }
  const { data } = await apiClient.post<CreateSearchResult>('/v1/search/face', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });

  const deadline = Date.now() + SEARCH_STATUS_POLL_TIMEOUT_MS;
  let latest = data;
  while (latest.search.status === 'queued' || latest.search.status === 'processing') {
    if (Date.now() >= deadline) {
      return latest;
    }
    await sleep(SEARCH_STATUS_POLL_INTERVAL_MS);
    latest = await getSearchStatus(latest.search.id);
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
