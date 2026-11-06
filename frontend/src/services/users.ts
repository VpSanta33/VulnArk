import { apiClient, buildQueryString } from './api';
import { User, Role, PaginatedResponse, SearchParams } from '../types/api';

export interface CreateUserRequest {
  username: string;
  real_name: string;
  email: string;
  phone?: string;
  department?: string;
  password: string;
  role_id: number;
}

export interface UpdateUserRequest {
  real_name?: string;
  email?: string;
  phone?: string;
  department?: string;
  role_id?: number;
  status?: number;
}

export interface UserSearchParams extends SearchParams {
  role_id?: number;
  department?: string;
  status?: number;
}

export class UsersService {
  // Get users list with pagination and filtering
  async getUsers(params: UserSearchParams = {}, signal?: AbortSignal): Promise<PaginatedResponse<User>> {
    const queryString = buildQueryString(params);
    const response = await apiClient.get<PaginatedResponse<User>>(`/users${queryString}`, { signal });
    return response.data!;
  }

  // Get user by ID
  async getUser(id: number): Promise<User> {
    const response = await apiClient.get<User>(`/users/${id}`);
    return response.data!;
  }

  // Create new user
  async createUser(data: CreateUserRequest): Promise<User> {
    const response = await apiClient.post<User>('/users', data);
    return response.data!;
  }

  // Update user
  async updateUser(id: number, data: UpdateUserRequest): Promise<User> {
    const response = await apiClient.put<User>(`/users/${id}`, data);
    return response.data!;
  }

  // Delete user
  async deleteUser(id: number): Promise<void> {
    await apiClient.delete(`/users/${id}`);
  }

  // Get all roles
  async getRoles(): Promise<Role[]> {
    const response = await apiClient.get<Role[]>('/roles');
    return response.data!;
  }

  // Get user statistics
  async getUserStats(): Promise<unknown> {
    const response = await apiClient.get('/users/stats');
    return response.data!;
  }

  // Reset user password
  async resetPassword(id: number, newPassword: string): Promise<void> {
    await apiClient.post(`/users/${id}/reset-password`, { password: newPassword });
  }

  // Get user status options
  getUserStatusOptions(): Array<{ value: number; label: string; color: string }> {
    return [
      { value: 1, label: '正常', color: 'green' },
      { value: 0, label: '禁用', color: 'red' },
    ];
  }

  // Get departments (mock data - replace with API call if available)
  getDepartments(): string[] {
    return [
      '技术部',
      '安全部',
      '运维部',
      '产品部',
      '市场部',
      '人事部',
      '财务部',
    ];
  }
}

export const usersService = new UsersService();
