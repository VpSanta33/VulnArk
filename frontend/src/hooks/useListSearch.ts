import { useCallback, useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';

// Keep input responsive while coalescing requests and resetting pagination.
export function useSearchKeyword<T extends { keyword?: string; page?: number }>(
  setParams: Dispatch<SetStateAction<T>>, delay = 300,
) {
  const [keyword, setKeyword] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => {
      setParams(previous => previous.keyword === keyword ? previous : { ...previous, keyword, page: 1 });
    }, delay);
    return () => clearTimeout(timer);
  }, [keyword, delay, setParams]);
  return [keyword, setKeyword] as const;
}

// Invalidate stale results even when a transport ignores cancellation.
export function useLatestRequest() {
  const active = useRef<AbortController | null>(null);
  const cancel = useCallback(() => {
    active.current?.abort();
    active.current = null;
  }, []);
  const begin = useCallback(() => {
    cancel();
    const controller = new AbortController();
    active.current = controller;
    return {
      signal: controller.signal,
      isCurrent: () => active.current === controller && !controller.signal.aborted,
    };
  }, [cancel]);
  useEffect(() => cancel, [cancel]);
  return { begin, cancel };
}
