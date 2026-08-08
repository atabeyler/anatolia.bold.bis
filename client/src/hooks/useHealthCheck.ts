import { useQuery } from '@tanstack/react-query';

import { apiClient } from '../services/apiClient';

interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

export function useHealthCheck() {
  return useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const { data } = await apiClient.get<HealthResponse>('/health');
      return data;
    },
    retry: 1,
  });
}
