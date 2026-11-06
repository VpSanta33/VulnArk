import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getErrorMessage(error: unknown, fallback: string): string {
  if (!error || typeof error !== 'object') return fallback;
  const value = error as {
    message?: unknown;
    response?: { data?: { message?: unknown } };
  };
  const message = value.response?.data?.message || value.message;
  return typeof message === 'string' && message ? message : fallback;
}
