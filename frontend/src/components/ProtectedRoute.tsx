import React, { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface ProtectedRouteProps {
  children: ReactNode;
  requiredPermissions?: string[];
}

export function ProtectedRoute({ children, requiredPermissions }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasPermission } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    // Redirect to login page with return url
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredPermissions?.some(permission => !hasPermission(permission))) {
    return <div role="alert" className="rounded-lg border border-gray-200 bg-white p-8 text-center space-y-3">
      <h1 className="text-xl font-semibold">无权访问此页面</h1>
      <p className="text-gray-600">您的角色没有此功能所需的权限，请通过菜单访问可用功能。</p>
    </div>;
  }

  return <>{children}</>;
}
