import { lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  User,
  Settings as SettingsIcon,
  Shield,
  Bell,
  Bot,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
const ProfileSettings = lazy(() => import('../components/settings/ProfileSettings').then(m => ({ default: m.ProfileSettings })));
const SecuritySettings = lazy(() => import('../components/settings/SecuritySettings').then(m => ({ default: m.SecuritySettings })));
const SystemSettings = lazy(() => import('../components/settings/SystemSettings').then(m => ({ default: m.SystemSettings })));
const NotificationSettings = lazy(() => import('../components/settings/NotificationSettings').then(m => ({ default: m.NotificationSettings })));
const AISettings = lazy(() => import('../components/settings/AISettings').then(m => ({ default: m.AISettings })));
const SLASettings = lazy(() => import('../components/settings/SLASettings').then(m => ({ default: m.SLASettings })));
type SettingsTab = 'profile' | 'security' | 'system' | 'notifications' | 'ai' | 'sla';

interface SettingsTabConfig {
  id: SettingsTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  badge?: string;
  permission?: string;
}

const settingsTabs: SettingsTabConfig[] = [
  { id: 'sla', label: 'SLA 策略', icon: Shield, description: '响应、修复期限与匹配策略', permission: 'sla:manage' },
  {
    id: 'profile',
    label: '个人资料',
    icon: User,
    description: '管理个人信息和偏好设置',
  },
  {
    id: 'security',
    label: '安全设置',
    icon: Shield,
    description: '密码、双因素认证和安全选项',
    badge: '重要',
  },
  {
    id: 'system',
    label: '系统配置',
    icon: SettingsIcon,
    description: '主题、语言和界面设置',
  },
  {
    id: 'notifications',
    label: '通知设置',
    icon: Bell,
    description: '邮件提醒和系统通知配置',
  },
  {
    id: 'ai',
    label: 'AI助手',
    icon: Bot,
    description: 'AI助手配置和管理',
  },
];

export function Settings() {
  const { hasPermission } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const allowedTabs = settingsTabs.filter(tab => !tab.permission || hasPermission(tab.permission));
  const activeTab = allowedTabs.find(tab => tab.id === searchParams.get('tab'))?.id || 'profile';
  const setActiveTab = (tab: SettingsTab) => { const next = new URLSearchParams(searchParams); next.set('tab', tab); setSearchParams(next); };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'sla':
        return <SLASettings />;
      case 'profile':
        return <ProfileSettings />;
      case 'security':
        return <SecuritySettings />;
      case 'system':
        return <SystemSettings />;
      case 'notifications':
        return <NotificationSettings />;
      case 'ai':
        return <AISettings />;
      default:
        return <ProfileSettings />;
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in-0 duration-700">
      {/* Header */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
          <SettingsIcon className="h-8 w-8 text-blue-600" />
          系统设置
        </h1>
        <p className="text-gray-600">
          管理您的账户、安全设置和系统配置
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-4">
        {/* Settings Navigation */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">设置分类</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <nav className="space-y-1">
                {allowedTabs.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;
                  
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-gray-50 ${
                        isActive 
                          ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-600' 
                          : 'text-gray-700 hover:text-gray-900'
                      }`}
                    >
                      <Icon className={`h-5 w-5 ${isActive ? 'text-blue-600' : 'text-gray-500'}`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{tab.label}</span>
                          {tab.badge && (
                            <Badge variant="destructive" className="text-xs">
                              {tab.badge}
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-gray-500 mt-1 truncate">
                          {tab.description}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </nav>
            </CardContent>
          </Card>


        </div>

        {/* Settings Content */}
        <div className="lg:col-span-3">
          <div className="animate-in slide-in-from-right-4 duration-500">
            <Suspense fallback={<p role="status">正在加载设置…</p>}>{renderTabContent()}</Suspense>
          </div>
        </div>
      </div>
    </div>
  );
}
