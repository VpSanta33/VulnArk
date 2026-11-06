import { apiClient, buildQueryString } from './api';
import {
  Asset,
  CreateAssetRequest,
  AssetSearchParams,
  PaginatedResponse,
} from '../types/api';

export class AssetsService {
  // Get assets list with pagination and filtering
  async getAssets(params: AssetSearchParams = {}, signal?: AbortSignal): Promise<PaginatedResponse<Asset>> {
    const queryString = buildQueryString(params);
    const response = await apiClient.get<PaginatedResponse<Asset>>(`/assets${queryString}`, { signal });
    return response.data!;
  }

  // Get asset by ID
  async getAsset(id: number): Promise<Asset> {
    const response = await apiClient.get<Asset>(`/assets/${id}`);
    return response.data!;
  }

  // Create new asset
  async createAsset(data: CreateAssetRequest): Promise<Asset> {
    const response = await apiClient.post<Asset>('/assets', data);
    return response.data!;
  }

  // Update asset
  async updateAsset(id: number, data: Partial<CreateAssetRequest>): Promise<Asset> {
    const response = await apiClient.put<Asset>(`/assets/${id}`, data);
    return response.data!;
  }

  // Delete asset
  async deleteAsset(id: number): Promise<void> {
    await apiClient.delete(`/assets/${id}`);
  }

  // Get asset statistics
  async getAssetStats(): Promise<unknown> {
    const response = await apiClient.get('/assets/stats');
    return response.data!;
  }

  // Get asset types
  async getAssetTypes(): Promise<string[]> {
    const response = await apiClient.get<string[]>('/assets/types');
    return response.data!;
  }

  // Get importance levels
  getImportanceLevels(): Array<{ value: number; label: string; color: string }> {
    return [
      { value: 1, label: '高', color: 'red' },
      { value: 2, label: '中', color: 'yellow' },
      { value: 3, label: '低', color: 'blue' },
    ];
  }

  // Bulk import assets
  async importAssets(file: File): Promise<unknown> {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await apiClient.upload('/assets/import', formData);
    return response.data!;
  }
}

export const assetsService = new AssetsService();

// Re-export types for convenience
export type { AssetSearchParams } from '../types/api';
