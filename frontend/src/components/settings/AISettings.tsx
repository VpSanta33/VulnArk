import { getErrorMessage } from '../../lib/utils';
import React, { useState, useEffect } from 'react';
import {
  Bot,
  Settings,
  Key,
  TestTube,
  CheckCircle,
  AlertCircle,
  Loader2,
  Save,
  Eye,
  EyeOff,
  HelpCircle,
  Zap,
  Globe,
  Clock,
  Thermometer,
  Hash
} from 'lucide-react';

import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Switch } from '../ui/Switch';
import { Badge } from '../ui/Badge';

import {
  aiService,
  AIProvider,
  AIConfigurationRequest
} from '../../services/aiService';

export const AISettings: React.FC = () => {
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [hasSavedKey, setHasSavedKey] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // 表单状态
  const [formData, setFormData] = useState<AIConfigurationRequest>({
    provider: 'openai',
    api_key: '',
    api_url: '',
    model: '',
    max_tokens: 2000,
    temperature: 0.7,
    timeout: 30,
    enabled: false
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [configData, providersData] = await Promise.all([
        aiService.getAIConfiguration(),
        aiService.getSupportedProviders()
      ]);

      setProviders(providersData);
      setHasSavedKey(!!configData.has_api_key);

      // 设置表单数据
      setFormData({
        provider: configData.provider || 'openai',
        api_key: '', // 不显示现有密钥
        clear_api_key: false,
        api_url: configData.api_url || '',
        model: configData.model || '',
        max_tokens: configData.max_tokens || 2000,
        temperature: configData.temperature || 0.7,
        timeout: configData.timeout || 30,
        enabled: configData.enabled || false
      });

      // 如果没有设置模型，使用默认模型
      if (!configData.model && configData.provider) {
        const provider = providersData.find(p => p.id === configData.provider);
        if (provider) {
          setFormData(prev => ({ ...prev, model: provider.default_model }));
        }
      }

    } catch (err: unknown) {
      setError(getErrorMessage(err, '加载AI配置失败'));
    } finally {
      setLoading(false);
    }
  };

  const handleProviderChange = (provider: string) => {
    const providerInfo = providers.find(p => p.id === provider);
    setFormData(prev => ({
      ...prev,
      provider,
      model: providerInfo?.default_model || '',
      api_url: providerInfo?.api_url || ''
    }));
    setTestResult(null);
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError('');
      setSuccess('');

      // 验证配置
      const errors = aiService.validateConfiguration(formData, hasSavedKey);
      if (errors.length > 0) {
        setError(errors.join('; '));
        return;
      }

      await aiService.saveAIConfiguration(formData);
      setSuccess('AI配置保存成功');
      
      // 重新加载配置
      await loadData();
    } catch (err: unknown) {
      setError(getErrorMessage(err, '保存AI配置失败'));
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    try {
      setTesting(true);
      setTestResult(null);

      if (!formData.api_key) {
        setTestResult({ success: false, message: '请输入API密钥' });
        return;
      }

      await aiService.testAIConnection({
        provider: formData.provider,
        api_key: formData.api_key,
        api_url: formData.api_url,
        model: formData.model,
        test_message: '这是一个连接测试消息'
      });

      setTestResult({ success: true, message: 'AI连接测试成功' });
    } catch (err: unknown) {
      setTestResult({ success: false, message: getErrorMessage(err, '连接测试失败') });
    } finally {
      setTesting(false);
    }
  };

  const selectedProvider = providers.find(p => p.id === formData.provider);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">加载AI配置...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 状态消息 */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md flex items-center gap-2">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 border border-green-200 text-green-600 px-4 py-3 rounded-md flex items-center gap-2">
          <CheckCircle className="h-4 w-4" />
          {success}
        </div>
      )}

      {/* AI助手配置 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-blue-500" />
            AI助手配置
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* 启用开关 */}
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium text-gray-700">启用AI助手</label>
              <p className="text-xs text-gray-500 mt-1">开启后可使用AI助手功能</p>
            </div>
            <Switch
              checked={formData.enabled}
              onChange={(enabled: boolean) => setFormData(prev => ({ ...prev, enabled }))}
            />
          </div>

          {/* AI提供商选择 */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              AI提供商
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {providers.map((provider) => (
                <button
                  key={provider.id}
                  onClick={() => handleProviderChange(provider.id)}
                  className={`p-4 border-2 rounded-lg transition-all hover:border-blue-300 ${
                    formData.provider === provider.id
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <div className="text-left">
                    <div className={`font-medium ${
                      formData.provider === provider.id ? 'text-blue-900' : 'text-gray-700'
                    }`}>
                      {provider.name}
                    </div>
                    <div className="text-xs text-gray-500 mt-1">
                      {provider.description}
                    </div>
                    {formData.provider === provider.id && (
                      <Badge variant="default" className="mt-2 text-xs">
                        已选择
                      </Badge>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* API配置 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* API密钥 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                API密钥
                <span className="text-gray-400 text-xs ml-1">{hasSavedKey ? '(已保存)' : '(启用时必填)'}</span>
              </label>
              <div className="relative">
                <Input
                  type={showApiKey ? 'text' : 'password'}
                  value={formData.api_key}
                  onChange={(e) => setFormData(prev => ({ ...prev, api_key: e.target.value, clear_api_key: false }))}
                  placeholder={hasSavedKey ? '留空保留已保存的密钥' : '输入API密钥'}
                  className="pr-10"
                />
                <button
                  type="button"
                  aria-label={showApiKey ? '隐藏API密钥' : '显示API密钥'}
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {hasSavedKey && <label className="mt-2 flex items-center gap-2 text-sm text-gray-600">
                <input type="checkbox" checked={!!formData.clear_api_key} disabled={formData.enabled}
                  onChange={e => setFormData(prev => ({ ...prev, clear_api_key: e.target.checked, api_key: '' }))} />
                保存时删除已保存的密钥（请先停用AI助手）
              </label>}
            </div>

            {/* API地址 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                API地址
                <span className="text-gray-400 text-xs ml-1">(可选)</span>
              </label>
              <Input
                type="url"
                value={formData.api_url}
                onChange={(e) => setFormData(prev => ({ ...prev, api_url: e.target.value }))}
                placeholder={selectedProvider?.api_url || '使用默认地址'}
              />
            </div>
          </div>

          {/* 模型选择 */}
          {selectedProvider && selectedProvider.models.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                模型选择
              </label>
              <Select
                value={formData.model}
                onChange={(e) => setFormData(prev => ({ ...prev, model: e.target.value }))}
                options={selectedProvider.models.map(model => ({
                  value: model,
                  label: aiService.getModelDisplayName(model)
                }))}
              />
            </div>
          )}

          {/* 高级参数 */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* 最大Token数 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                <Hash className="h-3 w-3 inline mr-1" />
                最大Token数
              </label>
              <Input
                type="number"
                min="1"
                max="32000"
                value={formData.max_tokens}
                onChange={(e) => setFormData(prev => ({ ...prev, max_tokens: parseInt(e.target.value) || 2000 }))}
              />
            </div>

            {/* 温度参数 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                <Thermometer className="h-3 w-3 inline mr-1" />
                温度参数
              </label>
              <Input
                type="number"
                min="0"
                max="2"
                step="0.1"
                value={formData.temperature}
                onChange={(e) => setFormData(prev => ({ ...prev, temperature: parseFloat(e.target.value) || 0.7 }))}
              />
            </div>

            {/* 超时时间 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                <Clock className="h-3 w-3 inline mr-1" />
                超时时间(秒)
              </label>
              <Input
                type="number"
                min="5"
                max="300"
                value={formData.timeout}
                onChange={(e) => setFormData(prev => ({ ...prev, timeout: parseInt(e.target.value) || 30 }))}
              />
            </div>
          </div>

          {/* 连接测试结果 */}
          {testResult && (
            <div className={`p-3 rounded-md flex items-center gap-2 ${
              testResult.success 
                ? 'bg-green-50 border border-green-200 text-green-700'
                : 'bg-red-50 border border-red-200 text-red-700'
            }`}>
              {testResult.success ? (
                <CheckCircle className="h-4 w-4" />
              ) : (
                <AlertCircle className="h-4 w-4" />
              )}
              {testResult.message}
            </div>
          )}

          {/* 操作按钮 */}
          <div className="flex gap-3 pt-4 border-t">
            <Button
              onClick={handleTest}
              disabled={testing || !formData.api_key}
              variant="outline"
              className="flex items-center gap-2"
            >
              {testing ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <TestTube className="h-4 w-4" />
              )}
              测试连接
            </Button>

            <Button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2"
            >
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              保存配置
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 使用说明 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <HelpCircle className="h-5 w-5 text-green-500" />
            使用说明
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm text-gray-600">
            <div className="flex items-start gap-2">
              <Zap className="h-4 w-4 text-yellow-500 mt-0.5 flex-shrink-0" />
              <div>
                <strong>AI助手功能：</strong>
                配置完成后，您可以使用AI助手获得系统配置指导、语言设置建议、日期时间格式推荐等帮助。
              </div>
            </div>
            <div className="flex items-start gap-2">
              <Key className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
              <div>
                <strong>API密钥：</strong>
                请从对应的AI服务提供商获取API密钥。密钥将被安全存储，不会在界面中显示。
              </div>
            </div>
            <div className="flex items-start gap-2">
              <Settings className="h-4 w-4 text-purple-500 mt-0.5 flex-shrink-0" />
              <div>
                <strong>参数调节：</strong>
                温度参数控制回答的创造性（0-2），Token数控制回答长度，超时时间影响响应速度。
              </div>
            </div>
            <div className="flex items-start gap-2">
              <Globe className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
              <div>
                <strong>提供商选择：</strong>
                不同提供商有不同的特点和定价，请根据需求选择合适的服务。
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
