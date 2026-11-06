import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Layout } from './components/Layout';
import { ErrorBoundary } from './components/ErrorBoundary';

const Login = lazy(() => import('./pages/Login').then(m => ({ default: m.Login })));
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const TestComponents = lazy(() => import('./pages/TestComponents').then(m => ({ default: m.TestComponents })));
const Users = lazy(() => import('./pages/Users').then(m => ({ default: m.Users })));
const Assets = lazy(() => import('./pages/Assets').then(m => ({ default: m.Assets })));
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities').then(m => ({ default: m.Vulnerabilities })));
const Reports = lazy(() => import('./pages/Reports').then(m => ({ default: m.Reports })));
const Analytics = lazy(() => import('./pages/Analytics').then(m => ({ default: m.Analytics })));
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })));
const AIAssistantPage = lazy(() => import('./pages/AIAssistant').then(m => ({ default: m.AIAssistantPage })));
const Knowledge = lazy(() => import('./pages/Knowledge').then(m => ({ default: m.Knowledge })));
const KnowledgeDetail = lazy(() => import('./pages/KnowledgeDetail').then(m => ({ default: m.KnowledgeDetail })));
const Notifications = lazy(() => import('./pages/Notifications').then(m => ({ default: m.Notifications })));

function App() {
  return <ThemeProvider><AuthProvider><Router><ErrorBoundary>
    <Suspense fallback={<div role="status" className="p-12 text-center text-gray-500">正在加载页面…</div>}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/*" element={<ProtectedRoute><Layout><Routes>
          <Route path="/" element={<ProtectedRoute requiredPermissions={['analytics:read']}><Dashboard /></ProtectedRoute>} />
          <Route path="/test" element={<ProtectedRoute requiredPermissions={['system:config']}><TestComponents /></ProtectedRoute>} />
          <Route path="/vulnerabilities" element={<ProtectedRoute requiredPermissions={['vuln:read']}><Vulnerabilities /></ProtectedRoute>} />
          <Route path="/assets" element={<ProtectedRoute requiredPermissions={['asset:read']}><Assets /></ProtectedRoute>} />
          <Route path="/reports" element={<ProtectedRoute requiredPermissions={['report:read']}><Reports /></ProtectedRoute>} />
          <Route path="/analytics" element={<ProtectedRoute requiredPermissions={['analytics:read']}><Analytics /></ProtectedRoute>} />
          <Route path="/users" element={<ProtectedRoute requiredPermissions={['user:manage']}><Users /></ProtectedRoute>} />
          <Route path="/knowledge" element={<ProtectedRoute requiredPermissions={['knowledge:read']}><Knowledge /></ProtectedRoute>} />
          <Route path="/knowledge/:id" element={<ProtectedRoute requiredPermissions={['knowledge:read']}><KnowledgeDetail /></ProtectedRoute>} />
          <Route path="/ai-assistant" element={<AIAssistantPage />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes></Layout></ProtectedRoute>} />
      </Routes>
    </Suspense>
  </ErrorBoundary></Router></AuthProvider></ThemeProvider>;
}

export default App;
