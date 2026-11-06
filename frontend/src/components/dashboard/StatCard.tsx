import React, { useEffect, useState } from 'react';
import { LucideIcon } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { cn } from '../../lib/utils';

interface StatCardProps {
  title: string;
  value: number;
  previousValue?: number;
  icon: LucideIcon;
  color: string;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: number;
  description?: string;
  className?: string;
  style?: React.CSSProperties;
}

export function StatCard({
  title,
  value,
  previousValue,
  icon: Icon,
  color,
  trendValue,
  description,
  className,
  style,
}: StatCardProps) {
  const [displayValue, setDisplayValue] = useState(0);
  const [isAnimating, setIsAnimating] = useState(false);

  // Animate number counting
  useEffect(() => {
    setIsAnimating(true);
    const duration = 1000; // 1 second
    const steps = 60;
    const increment = value / steps;
    let current = 0;
    let step = 0;

    const timer = setInterval(() => {
      step++;
      current = Math.min(increment * step, value);
      setDisplayValue(Math.floor(current));

      if (step >= steps) {
        clearInterval(timer);
        setDisplayValue(value);
        setIsAnimating(false);
      }
    }, duration / steps);

    return () => clearInterval(timer);
  }, [value]);

  // Calculate trend
  const calculateTrend = () => {
    if (trendValue !== undefined) {
      return {
        value: trendValue,
        isPositive: trendValue > 0,
      };
    }

    if (previousValue !== undefined && previousValue > 0) {
      const change = ((value - previousValue) / previousValue) * 100;
      return {
        value: Math.abs(change),
        isPositive: change > 0,
      };
    }

    return null;
  };

  const trendData = calculateTrend();

  return (
    <Card style={style} className={cn(
      'relative overflow-hidden transition-all duration-300 hover:shadow-lg hover:-translate-y-1 group',
      className
    )}>
      {/* Background gradient */}
      <div className={cn(
        'absolute inset-0 opacity-5 group-hover:opacity-10 transition-opacity duration-300',
        color.replace('text-', 'bg-')
      )} />
      
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-gray-600 group-hover:text-gray-900 transition-colors">
          {title}
        </CardTitle>
        <div className={cn(
          'p-2 rounded-lg transition-all duration-300 group-hover:scale-110',
          color.replace('text-', 'bg-').replace('600', '100'),
        )}>
          <Icon className={cn('h-4 w-4', color)} />
        </div>
      </CardHeader>
      
      <CardContent>
        <div className="space-y-2">
          <div className="flex items-baseline gap-2">
            <div className={cn(
              'text-2xl font-bold transition-all duration-300',
              isAnimating ? 'text-blue-600' : 'text-gray-900'
            )}>
              {displayValue.toLocaleString()}
            </div>
            
            {trendData && (
              <div className={cn(
                'flex items-center text-xs font-medium px-2 py-1 rounded-full',
                trendData.isPositive 
                  ? 'text-green-700 bg-green-100' 
                  : 'text-red-700 bg-red-100'
              )}>
                <span className="mr-1">
                  {trendData.isPositive ? '↗' : '↘'}
                </span>
                {trendData.value.toFixed(1)}%
              </div>
            )}
          </div>
          
          {description && (
            <p className="text-xs text-gray-500 group-hover:text-gray-600 transition-colors">
              {description}
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// Quick stats grid component
export function StatsGrid({ 
  stats, 
  className 
}: { 
  stats: Array<Omit<StatCardProps, 'className'>>; 
  className?: string;
}) {
  return (
    <div className={cn(
      'grid gap-4 md:grid-cols-2 lg:grid-cols-4',
      className
    )}>
      {stats.map((stat, index) => (
        <StatCard
          key={index}
          {...stat}
          className="animate-in slide-in-from-bottom-4 duration-500"
          style={{ animationDelay: `${index * 100}ms` } as React.CSSProperties}
        />
      ))}
    </div>
  );
}
