import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, LoginRequest } from '../types/api';
import { isLoginChallenge, isLoginRebindRequired, LoginResult, LoginVerification } from '../types/auth';
import { authService } from '../services/auth';
import { permissionGranted } from '../lib/permissions';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginRequest, verification?: LoginVerification) => Promise<LoginResult>;
  logout: () => Promise<void>;
  clearSession: () => void;
  updateUser: (userData: Partial<User>) => void;
  refreshUser: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const isAuthenticated = !!user && authService.isAuthenticated();

  // Initialize auth state on app start
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        if (authService.isAuthenticated()) {
          const userData = await authService.getProfile();
          setUser(userData);
        }
      } catch (error) {
        console.error('Failed to initialize auth:', error);
        authService.clearSession();
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const login = async (credentials: LoginRequest, verification?: LoginVerification) => {
    setIsLoading(true);
    try {
      const response = await authService.login(credentials, verification);
      if (isLoginChallenge(response) || isLoginRebindRequired(response)) {
        setUser(null);
        return response;
      }

      if (!('token' in response) || !('user' in response)) {
        throw new Error('登录响应无效，请重试');
      }

      setUser(response.user);
      return response;
    } finally {
      setIsLoading(false);
    }
  };

  const clearSession = () => {
    authService.clearSession();
    setUser(null);
  };

  const logout = async () => {
    try {
      await authService.logout();
    } finally {
      setUser(null);
    }
  };

  const updateUser = (userData: Partial<User>) => {
    if (user) {
      setUser({ ...user, ...userData });
    }
  };

  const refreshUser = async () => {
    try {
      if (authService.isAuthenticated()) {
        const userData = await authService.getProfile();
        setUser(userData);
      }
    } catch (error) {
      console.error('Failed to refresh user:', error);
      clearSession();
    }
  };

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    logout,
    clearSession,
    updateUser,
    refreshUser,
    hasPermission: permission => permissionGranted(user?.role?.permissions, permission),
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// The hook must remain colocated with its provider for the public auth-context API.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
