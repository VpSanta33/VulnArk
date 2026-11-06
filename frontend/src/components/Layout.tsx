import { ReactNode, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Home,
  Shield,
  Server,
  FileText,
  BarChart3,
  Users,
  Settings,
  Bot,
  BookOpen,
  LogOut,
  Menu,
  X,
  Bell
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { Button } from './ui/Button';
import { cn } from '../lib/utils';


interface LayoutProps {
  children: ReactNode;
}

const navigation = [
  { name: '仪表板', href: '/', icon: Home, permission: 'analytics:read' },
  { name: '漏洞管理', href: '/vulnerabilities', icon: Shield, permission: 'vuln:read' },
  { name: '资产管理', href: '/assets', icon: Server, permission: 'asset:read' },
  { name: '报告管理', href: '/reports', icon: FileText, permission: 'report:read' },
  { name: '知识库', href: '/knowledge', icon: BookOpen, permission: 'knowledge:read' },
  { name: '统计分析', href: '/analytics', icon: BarChart3, permission: 'analytics:read' },
  { name: '用户管理', href: '/users', icon: Users, permission: 'user:manage' },
  { name: '站内通知', href: '/notifications', icon: Bell },
  { name: 'AI 助手', href: '/ai-assistant', icon: Bot },
  { name: '系统设置', href: '/settings', icon: Settings },
];

export function Layout({ children }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const { user, logout, hasPermission } = useAuth();
  const allowedNavigation = navigation.filter(item => !item.permission || hasPermission(item.permission));
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);
    try {
      await logout();
      navigate('/login', { replace: true });
    } catch {
      navigate('/login', { replace: true, state: { message: '已退出本机，但无法确认服务器会话已撤销。请检查网络后重新登录并撤销所有会话。' } });
    } finally {
      setLoggingOut(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar */}
      <div className={cn(
        'fixed inset-0 z-50 lg:hidden',
        sidebarOpen ? 'block' : 'hidden'
      )}>
        <div className="fixed inset-0 bg-gray-600 bg-opacity-75" onClick={() => setSidebarOpen(false)} />
        <div className="fixed inset-y-0 left-0 flex w-64 flex-col bg-white shadow-xl">
          <div className="flex h-16 items-center justify-between px-4">
            <h1 className="text-xl font-bold text-gray-900">VulnArk</h1>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSidebarOpen(false)}
            >
              <X className="h-6 w-6" />
            </Button>
          </div>
          <nav className="flex-1 space-y-1 px-2 py-4">
            {allowedNavigation.map((item) => {
              const isActive = item.href === '/' ? location.pathname === '/' : location.pathname.startsWith(item.href);
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={cn(
                    'group flex items-center px-2 py-2 text-sm font-medium rounded-md',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  )}
                  onClick={() => setSidebarOpen(false)}
                >
                  <item.icon className="mr-3 h-5 w-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col">
        <div className="flex flex-col flex-grow bg-white border-r border-gray-200">
          <div className="flex h-16 items-center px-4">
            <h1 className="text-xl font-bold text-gray-900">VulnArk</h1>
          </div>
          <nav className="flex-1 space-y-1 px-2 py-4">
            {allowedNavigation.map((item) => {
              const isActive = item.href === '/' ? location.pathname === '/' : location.pathname.startsWith(item.href);
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={cn(
                    'group flex items-center px-2 py-2 text-sm font-medium rounded-md',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  )}
                >
                  <item.icon className="mr-3 h-5 w-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-gray-200 bg-white px-4 shadow-sm sm:gap-x-6 sm:px-6 lg:px-8">
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-6 w-6" />
          </Button>

          <div className="flex flex-1 gap-x-4 self-stretch lg:gap-x-6">
            <div className="flex flex-1"></div>
            <div className="flex items-center gap-x-4 lg:gap-x-6">
              {/* User menu */}
              <div className="flex items-center gap-x-2">
                <div className="hidden lg:flex lg:flex-col lg:items-end lg:leading-6">
                  <span className="text-sm font-semibold text-gray-900">
                    {user?.real_name || user?.username}
                  </span>
                  <span className="text-xs text-gray-600">
                    {user?.role?.name}
                  </span>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleLogout} disabled={loggingOut}
                  title="退出登录"
                >
                  <LogOut className="h-5 w-5" />
                </Button>
              </div>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="py-6">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            {children}
          </div>
        </main>
      </div>


    </div>
  );
}
