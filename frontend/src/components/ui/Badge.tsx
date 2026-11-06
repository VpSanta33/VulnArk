import { HTMLAttributes, forwardRef } from 'react';
import { cn } from '../../lib/utils';

export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'destructive' | 'success' | 'warning' | 'outline' | 'medium' | 'low';
}

const Badge = forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant = 'default', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
          {
            'bg-gray-900 text-gray-50 hover:bg-gray-900/80': variant === 'default',
            'bg-gray-100 text-gray-900 hover:bg-gray-100/80': variant === 'secondary',
            'bg-red-500 text-gray-50 hover:bg-red-500/80': variant === 'destructive',
            'bg-green-500 text-gray-50 hover:bg-green-500/80': variant === 'success',
            'bg-orange-500 text-gray-50 hover:bg-orange-500/80': variant === 'warning',
            'bg-yellow-500 text-gray-900 hover:bg-yellow-500/80': variant === 'medium',
            'bg-blue-500 text-gray-50 hover:bg-blue-500/80': variant === 'low',
            'border border-gray-200 text-gray-900': variant === 'outline',
          },
          className
        )}
        {...props}
      />
    );
  }
);

Badge.displayName = 'Badge';

export { Badge };

// Predefined severity badges
export function SeverityBadge({ level, count }: { level: number; count?: number }) {
  const severityConfig = {
    1: { label: '严重', variant: 'destructive' as const, icon: '🔴' },
    2: { label: '高危', variant: 'warning' as const, icon: '🟠' },
    3: { label: '中危', variant: 'medium' as const, icon: '🟡' },
    4: { label: '低危', variant: 'low' as const, icon: '🔵' },
  };

  const config = severityConfig[level as keyof typeof severityConfig] || {
    label: `级别 ${level}`,
    variant: 'secondary' as const,
    icon: '⚪',
  };

  return (
    <Badge variant={config.variant} className="gap-1">
      <span>{config.icon}</span>
      <span>{config.label}</span>
      {count !== undefined && <span className="ml-1 font-bold">({count})</span>}
    </Badge>
  );
}

// Status badges for various entities
export function StatusBadge({ status }: { status: string }) {
  const statusConfig: Record<string, { variant: BadgeProps['variant']; label: string }> = {
    new: { variant: 'secondary', label: '新建' },
    assigned: { variant: 'warning', label: '已分配' },
    in_progress: { variant: 'secondary', label: '处理中' },
    fixed: { variant: 'success', label: '已修复' },
    verified: { variant: 'success', label: '已验证' },
    closed: { variant: 'outline', label: '已关闭' },
    active: { variant: 'success', label: '活跃' },
    inactive: { variant: 'outline', label: '非活跃' },
    published: { variant: 'success', label: '已发布' },
    draft: { variant: 'warning', label: '草稿' },
  };

  const config = statusConfig[status] || { variant: 'secondary' as const, label: status };

  return (
    <Badge variant={config.variant}>
      {config.label}
    </Badge>
  );
}
