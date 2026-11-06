import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { 
  Key,
  Smartphone,
  Eye,
  EyeOff,
  Save,
  X,
  CheckCircle,
  LogOut,
  Copy
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Badge } from '../ui/Badge';
import { settingsService, ChangePasswordRequest } from '../../services/settings';
import { getAuthError } from '../../types/auth';

const passwordSchema = z.object({
  current_password: z.string().min(1, '请输入当前密码'),
  new_password: z.string()
    .min(8, '新密码至少需要8个字符')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
      '密码必须包含大小写字母、数字和特殊字符'),
  confirm_password: z.string(),
}).refine((data) => data.new_password === data.confirm_password, {
  message: '确认密码不匹配',
  path: ['confirm_password'],
});

type PasswordFormData = z.infer<typeof passwordSchema>;

export function SecuritySettings() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [twoFactorPending, setTwoFactorPending] = useState(false);
  const [needsRebind, setNeedsRebind] = useState(false);
  const [recoveryCodesRemaining, setRecoveryCodesRemaining] = useState(0);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusReady, setStatusReady] = useState(false);
  const [show2FASetup, setShow2FASetup] = useState(false);
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [setupSecret, setSetupSecret] = useState('');
  const [setupExpiresAt, setSetupExpiresAt] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verificationCode, setVerificationCode] = useState('');
  const [codesCopied, setCodesCopied] = useState(false);
  const [disableCode, setDisableCode] = useState('');
  const [showRecoveryCodes, setShowRecoveryCodes] = useState(false);
  const navigate = useNavigate();
  const { clearSession } = useAuth();

  useEffect(() => {
    let active = true;
    settingsService.get2FAStatus()
      .then((status) => {
        if (!active) return;
        setTwoFactorEnabled(status.enabled);
        setTwoFactorPending(status.pending);
        setNeedsRebind(status.needs_rebind);
        setRecoveryCodesRemaining(status.recovery_codes_remaining);
        setStatusReady(true);
      })
      .catch((error: unknown) => {
        if (active) setError(getAuthError(error, '无法加载双因素认证状态').message);
      })
      .finally(() => {
        if (active) setStatusLoading(false);
      });

    return () => { active = false; };
  }, []);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isDirty },
  } = useForm<PasswordFormData>({
    resolver: zodResolver(passwordSchema),
  });

  const onSubmitPassword = async (data: PasswordFormData) => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');

      const changePasswordData: ChangePasswordRequest = {
        current_password: data.current_password,
        new_password: data.new_password,
        confirm_password: data.confirm_password,
      };

      await settingsService.changePassword(changePasswordData);
      clearSession();
      setSuccess('密码修改成功，请使用新密码重新登录');
      reset();
      navigate('/login', { replace: true, state: { message: '密码已修改，请使用新密码重新登录' } });
    } catch (error: unknown) {
      setError(getAuthError(error, '密码修改失败，请重试').message);
    } finally {
      setLoading(false);
    }
  };

  const togglePasswordVisibility = (field: keyof typeof showPasswords) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field],
    }));
  };

  const handleToggle2FA = async () => {
    setError('');
    setSuccess('');
    if (twoFactorEnabled) {
      if (!disableCode.trim()) {
        setError('请输入当前验证码或一个未使用的恢复码以禁用双因素认证');
        return;
      }
      try {
        setLoading(true);
        await settingsService.disable2FA(disableCode.trim());
        clearSession();
        navigate('/login', { replace: true, state: { message: '双因素认证已禁用，请重新登录' } });
      } catch (error: unknown) {
        setError(getAuthError(error, '禁用双因素认证失败，请重试').message);
      } finally {
        setLoading(false);
      }
      return;
    }

    try {
      setLoading(true);
      const setupData = await settingsService.setup2FA();
      setQrCodeUrl(setupData.qr_code_data_url);
      setSetupSecret(setupData.secret);
      setSetupExpiresAt(setupData.expires_at);
      setBackupCodes([]);
      setVerificationCode('');
      setShow2FASetup(true);
    } catch (error: unknown) {
      setError(getAuthError(error, '启用双因素认证失败，请重试').message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async () => {
    if (Date.parse(setupExpiresAt) <= Date.now()) {
      setError('双因素认证设置已过期，请取消后重新开始');
      return;
    }
    try {
      setLoading(true);
      setError('');
      const result = await settingsService.verify2FA(verificationCode.trim());
      setTwoFactorEnabled(true);
      setTwoFactorPending(false);
      setNeedsRebind(false);
      setRecoveryCodesRemaining(result.recovery_codes.length);
      setBackupCodes(result.recovery_codes);
      setShowRecoveryCodes(true);
      setShow2FASetup(false);
      setVerificationCode('');
      setSuccess('双因素认证已成功启用，请保存本次显示的恢复码');
    } catch (error: unknown) {
      setError(getAuthError(error, '验证码错误或设置已过期，请重试').message);
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeAllSessions = async () => {
    if (!window.confirm('确定退出此账户的所有会话吗？当前会话也将退出。')) return;
    try {
      setLoading(true);
      await settingsService.revokeAllSessions();
      clearSession();
      navigate('/login', { replace: true, state: { message: '已退出所有会话，请重新登录' } });
    } catch (error: unknown) {
      setError(getAuthError(error, '退出所有会话失败，请重试').message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div role="alert" className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md flex items-center gap-2">
          <X className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {success && (
        <div role="status" className="bg-green-50 border border-green-200 text-green-600 px-4 py-3 rounded-md flex items-center gap-2">
          <CheckCircle className="h-4 w-4 shrink-0" />
          <span>{success}</span>
        </div>
      )}
      {/* Password Change */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5 text-blue-500" />
            修改密码
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmitPassword)} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  当前密码 <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Input
                    type={showPasswords.current ? 'text' : 'password'}
                    {...register('current_password')}
                    error={errors.current_password?.message}
                    disabled={loading}
                    placeholder="请输入当前密码"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('current')}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.current ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  新密码 <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Input
                    type={showPasswords.new ? 'text' : 'password'}
                    {...register('new_password')}
                    error={errors.new_password?.message}
                    disabled={loading}
                    placeholder="请输入新密码"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('new')}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.new ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  确认新密码 <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Input
                    type={showPasswords.confirm ? 'text' : 'password'}
                    {...register('confirm_password')}
                    error={errors.confirm_password?.message}
                    disabled={loading}
                    placeholder="请再次输入新密码"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('confirm')}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.confirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
              <h4 className="text-sm font-medium text-blue-900 mb-2">密码要求：</h4>
              <ul className="text-sm text-blue-800 space-y-1">
                <li>• 至少8个字符</li>
                <li>• 包含大写字母</li>
                <li>• 包含小写字母</li>
                <li>• 包含数字</li>
                <li>• 包含特殊字符 (@$!%*?&)</li>
              </ul>
            </div>

            <div className="flex justify-end gap-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => reset()}
                disabled={loading || !isDirty}
              >
                重置
              </Button>
              <Button
                type="submit"
                disabled={loading || !isDirty}
                className="gap-2"
              >
                <Save className="h-4 w-4" />
                {loading ? '修改中...' : '修改密码'}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Two-Factor Authentication */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5 text-green-500" />
            双因素认证
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex-1">
                <h4 className="font-medium text-gray-900">双因素认证状态</h4>
                <p className="text-sm text-gray-600 mt-1">
                  {needsRebind
                    ? '检测到旧版模拟配置，请重新绑定真实身份验证器。'
                    : twoFactorPending
                      ? '认证器设置尚未完成，请扫描二维码并验证。'
                      : twoFactorEnabled
                        ? `账户受双因素认证保护，剩余恢复码 ${recoveryCodesRemaining} 个。`
                        : '为您的账户添加额外的安全保护层'}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={statusLoading ? 'secondary' : twoFactorEnabled ? 'success' : 'secondary'}>
                  {statusLoading ? '加载中' : twoFactorEnabled ? '已启用' : needsRebind ? '需重新绑定' : twoFactorPending ? '待完成' : '未启用'}
                </Badge>
                <Button
                  onClick={handleToggle2FA}
                  disabled={loading || statusLoading || !statusReady}
                  variant={twoFactorEnabled ? 'destructive' : 'default'}
                  size="sm"
                >
                  {twoFactorEnabled ? '禁用' : twoFactorPending ? '重新生成二维码' : '启用'}
                </Button>
              </div>
            </div>
            {twoFactorEnabled && (
              <div className="flex flex-col sm:flex-row gap-2 sm:items-center">
                <Input
                  value={disableCode}
                  onChange={(event) => setDisableCode(event.target.value)}
                  placeholder="输入当前验证码或恢复码以禁用"
                  aria-label="禁用双因素认证的验证码或恢复码"
                />
              </div>
            )}
            {twoFactorEnabled && recoveryCodesRemaining > 0 && (
              <p className="text-sm text-gray-600">恢复码仅在启用时显示一次，当前不支持重新查看。</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <LogOut className="h-5 w-5 text-red-600" />
            会话管理
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <p className="text-sm text-gray-600">
            立即撤销此账户的所有登录会话，包括当前会话。
          </p>
          <Button
            onClick={handleRevokeAllSessions}
            variant="destructive"
            disabled={loading}
            className="gap-2"
          >
            <LogOut className="h-4 w-4" />
            退出所有会话
          </Button>
        </CardContent>
      </Card>

      {showRecoveryCodes && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle>保存恢复码</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-gray-700">这些恢复码仅显示这一次。请保存在安全位置，关闭后无法再次查看。</p>
              <div className="grid grid-cols-2 gap-2 rounded-md border bg-gray-50 p-3 text-sm font-mono">
                {backupCodes.map((code) => <div key={code} className="break-all">{code}</div>)}
              </div>
              <div className="flex justify-end gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="gap-2"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(backupCodes.join('\\n'));
                      setCodesCopied(true);
                    } catch {
                      setError('无法访问剪贴板，请手动保存恢复码');
                    }
                  }}
                >
                  <Copy className="h-4 w-4" />
                  {codesCopied ? '已复制' : '复制恢复码'}
                </Button>
                <Button
                  type="button"
                  onClick={() => {
                    setShowRecoveryCodes(false);
                    setBackupCodes([]);
                    setCodesCopied(false);
                  }}
                >
                  我已保存
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* 2FA Setup Modal */}
      {show2FASetup && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Smartphone className="h-5 w-5 text-green-500" />
                设置双因素认证
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
              <div className="text-center">
                <p className="text-sm text-gray-600 mb-4">
                  请使用身份验证器扫描二维码。设置有效期至 {new Date(setupExpiresAt).toLocaleTimeString()}。
                </p>
                {qrCodeUrl && (
                  <div className="bg-white p-4 rounded-lg border inline-block">
                    <img src={qrCodeUrl} alt="双因素认证二维码" className="w-48 h-48" />
                  </div>
                )}
                {setupSecret && (
                  <p className="mt-3 break-all text-xs font-mono text-gray-600">密钥：{setupSecret}</p>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  验证码
                </label>
                <Input
                  type="text"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value)}
                  placeholder="请输入6位验证码"
                  maxLength={6}
                  className="text-center text-lg tracking-widest"
                />
              </div>

              <div className="flex justify-end gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShow2FASetup(false);
                    setVerificationCode('');
                  }}
                  disabled={loading}
                >
                  取消
                </Button>
                <Button
                  onClick={handleVerify2FA}
                  disabled={loading || verificationCode.length !== 6}
                  className="gap-2"
                >
                  <CheckCircle className="h-4 w-4" />
                  {loading ? '验证中...' : '验证并启用'}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
