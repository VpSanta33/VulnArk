import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect } from 'react';
import {
  Globe,
  Monitor,
  Save,
  CheckCircle,
  X
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Select } from '../ui/Select';

import { settingsService, SystemSettingsRequest } from '../../services/settings';
import { useTheme } from '../../contexts/ThemeContext';
import { useAuth } from '../../contexts/AuthContext';

export function SystemSettings() {
  const { theme, language, setTheme, setLanguage } = useTheme();
  const { isAuthenticated } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [timezone, setTimezone] = useState('Asia/Shanghai');
  const [dateFormat, setDateFormat] = useState('YYYY-MM-DD');
  const [timeFormat, setTimeFormat] = useState('24h');


  // 加载系统设置
  useEffect(() => {
    let isMounted = true;

    const loadSettings = async () => {
      // Only load settings if user is authenticated
      if (!isAuthenticated) {
        return;
      }

      try {
        const settings = await settingsService.getSystemSettings();
        if (isMounted) {
          // Theme and language are managed by ThemeContext, only load other settings
          setTimezone(settings.timezone);
          setDateFormat(settings.date_format);
          setTimeFormat(settings.time_format);
        }
      } catch (err) {
        if (isMounted) {
          console.error('Failed to load system settings:', err);
        }
      } finally {
        // Settings loaded
      }
    };

    loadSettings();

    return () => {
      isMounted = false;
    };
  }, [isAuthenticated]);



  const languageOptions = [
    { value: 'zh-CN', label: '简体中文' },
    { value: 'en-US', label: 'English' },
  ];

  const timezoneOptions = [
    { value: 'Asia/Shanghai', label: '中国标准时间 (UTC+8)' },
    { value: 'Asia/Tokyo', label: '日本标准时间 (UTC+9)' },
    { value: 'America/New_York', label: '美国东部时间 (UTC-5)' },
    { value: 'Europe/London', label: '格林威治标准时间 (UTC+0)' },
  ];

  const dateFormatOptions = [
    { value: 'YYYY-MM-DD', label: '2024-01-20' },
    { value: 'DD/MM/YYYY', label: '20/01/2024' },
    { value: 'MM/DD/YYYY', label: '01/20/2024' },
    { value: 'DD-MM-YYYY', label: '20-01-2024' },
  ];

  const timeFormatOptions = [
    { value: '24h', label: '24小时制 (14:30)' },
    { value: '12h', label: '12小时制 (2:30 PM)' },
  ];

  const handleSave = async () => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');

      const settingsData: SystemSettingsRequest = {
        theme,
        language,
        timezone,
        date_format: dateFormat,
        time_format: timeFormat as '12h' | '24h',
      };

      await settingsService.updateSystemSettings(settingsData);

      // Update theme context to apply changes immediately
      setTheme(theme);
      setLanguage(language);

      setSuccess('系统设置保存成功！');
    } catch (err: unknown) {
      setError(getErrorMessage(err, '保存失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md flex items-center gap-2">
          <X className="h-4 w-4" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 border border-green-200 text-green-600 px-4 py-3 rounded-md flex items-center gap-2">
          <CheckCircle className="h-4 w-4" />
          {success}
        </div>
      )}

      {/* Language & Region */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-green-500" />
            语言和地区
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                界面语言
              </label>
              <Select
                value={language}
                onChange={(e) => setLanguage(e.target.value as 'zh-CN' | 'en-US')}
                options={languageOptions}
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                时区设置
              </label>
              <Select
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                options={timezoneOptions}
                disabled={loading}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Date & Time Format */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5 text-blue-500" />
            日期时间格式
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                日期格式
              </label>
              <Select
                value={dateFormat}
                onChange={(e) => setDateFormat(e.target.value)}
                options={dateFormatOptions}
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                时间格式
              </label>
              <Select
                value={timeFormat}
                onChange={(e) => setTimeFormat(e.target.value)}
                options={timeFormatOptions}
                disabled={loading}
              />
            </div>
          </div>

          <div className="bg-gray-50 border border-gray-200 rounded-md p-4">
            <h4 className="text-sm font-medium text-gray-900 mb-2">预览效果：</h4>
            <div className="text-sm text-gray-700 space-y-1">
              <p>日期: {new Date().toLocaleDateString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
              }).replace(/\//g, dateFormat.includes('-') ? '-' : '/')}</p>
              <p>时间: {new Date().toLocaleTimeString('zh-CN', {
                hour12: timeFormat === '12h',
                hour: '2-digit',
                minute: '2-digit',
              })}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button
          onClick={handleSave}
          disabled={loading}
          className="gap-2"
        >
          <Save className="h-4 w-4" />
          {loading ? '保存中...' : '保存设置'}
        </Button>
      </div>
    </div>
  );
}
