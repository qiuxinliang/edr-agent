import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuthStore } from '@/store/authStore';

interface ShellOutputMessage {
  type: 'shell:output';
  endpoint_id: string;
  output: string;
  is_stderr: boolean;
  ts: string;
}

function resolveWsBaseUrl(): string {
  const envRaw = (import.meta as any).env?.VITE_WS_URL;
  const env = typeof envRaw === 'string' ? envRaw.trim().replace(/\/$/, '') : '';
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const sameOrigin = `${proto}//${location.host}`;
  if (!env) return sameOrigin;
  try {
    new URL(env.includes('://') ? env : `ws://${env}`);
    return env;
  } catch {
    return sameOrigin;
  }
}

export interface ShellWsState {
  output: string[];
  connected: boolean;
}

const MAX_OUTPUT_LINES = 2000;

export function useShellWs(endpointId: string, enabled: boolean) {
  const [state, setState] = useState<ShellWsState>({ output: [], connected: false });
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedByUser = useRef(false);

  const connect = useCallback(() => {
    if (!endpointId || !enabled) return;
    if (wsRef.current) return;

    const token = useAuthStore.getState().token;
    if (!token) return;

    closedByUser.current = false;

    const base = resolveWsBaseUrl();
    const wsUrl = new URL('/ws', base.includes('://') ? base : `ws://${base}`);
    wsUrl.searchParams.set('token', token);

    const ws = new WebSocket(wsUrl.toString());
    wsRef.current = ws;

    ws.onopen = () => {
      setState((s) => ({ ...s, connected: true }));
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return;
      try {
        const msg = JSON.parse(ev.data) as ShellOutputMessage;
        if (msg.type !== 'shell:output') return;
        if (msg.endpoint_id !== endpointId) return;
        setState((s) => {
          const next = [...s.output, msg.output];
          if (next.length > MAX_OUTPUT_LINES) {
            return { ...s, output: next.slice(next.length - MAX_OUTPUT_LINES) };
          }
          return { ...s, output: next };
        });
      } catch {
        /* ignore non-JSON frames */
      }
    };

    ws.onerror = () => {
      setState((s) => ({ ...s, connected: false }));
    };

    ws.onclose = () => {
      wsRef.current = null;
      setState((s) => ({ ...s, connected: false }));
      if (!closedByUser.current) {
        reconnectRef.current = setTimeout(() => connect(), 3000);
      }
    };
  }, [endpointId, enabled]);

  const disconnect = useCallback(() => {
    closedByUser.current = true;
    if (reconnectRef.current) {
      clearTimeout(reconnectRef.current);
      reconnectRef.current = null;
    }
    wsRef.current?.close();
    wsRef.current = null;
    setState((s) => ({ ...s, connected: false }));
  }, []);

  const clearOutput = useCallback(() => {
    setState((s) => ({ ...s, output: [] }));
  }, []);

  useEffect(() => {
    if (enabled && endpointId) {
      connect();
    }
    return () => disconnect();
  }, [endpointId, enabled, connect, disconnect]);

  return { ...state, disconnect, clearOutput };
}
