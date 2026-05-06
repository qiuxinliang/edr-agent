import { useState, useRef, useEffect, useCallback } from 'react';
import { Terminal, Send, ChevronRight, X, AlertTriangle, Loader2, Trash2, Power, Wifi, WifiOff } from 'lucide-react';
import { postShellOpen, postShellInput, postShellClose } from '@/api/shell_ext';
import { useShellWs } from '@/hooks/useShellWs';
import { unwrapResponseBody } from '@/api/envelope';

interface RtrShellPanelProps {
  endpointId: string;
  endpointName?: string;
  embedded?: boolean;
  onClose?: () => void;
}

const QUICK_COMMANDS = [
  'whoami', 'hostname', 'systeminfo',
  'tasklist', 'netstat -ano',
  'ipconfig /all', 'net user',
  'sc query', 'dir C:\\',
  'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
];

export default function RtrShellPanel({ endpointId, endpointName, embedded, onClose }: RtrShellPanelProps) {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [command, setCommand] = useState('');
  const [opening, setOpening] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wsEnabled, setWsEnabled] = useState(false);

  const { output, connected } = useShellWs(endpointId, wsEnabled);
  const inputRef = useRef<HTMLInputElement>(null);
  const outputRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  useEffect(() => {
    return () => {
      if (sessionId) {
        postShellClose(endpointId, { session_id: sessionId }).catch(() => {});
      }
    };
  }, [endpointId, sessionId]);

  const openSession = useCallback(async () => {
    if (!endpointId || opening || sessionId) return;
    setOpening(true);
    setError(null);
    try {
      const res = await postShellOpen(endpointId);
      const data = unwrapResponseBody<{ task_id: string; status: string }>(res.data);
      setSessionId(data.task_id);
      setWsEnabled(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : '打开 Shell 会话失败');
    } finally {
      setOpening(false);
    }
  }, [endpointId, opening, sessionId]);

  const closeSession = useCallback(async () => {
    if (!sessionId) return;
    setWsEnabled(false);
    try {
      await postShellClose(endpointId, { session_id: sessionId });
    } catch {
      /* best effort */
    }
    setSessionId(null);
  }, [endpointId, sessionId]);

  const sendInput = useCallback(async (input: string) => {
    if (!sessionId || !input.trim() || sending) return;
    setSending(true);
    try {
      await postShellInput(endpointId, { session_id: sessionId, input: input.trim() });
      setCommand('');
    } catch (e) {
      setError(e instanceof Error ? e.message : '发送命令失败');
    } finally {
      setSending(false);
    }
  }, [endpointId, sessionId, sending]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!sessionId) {
        openSession().then(() => {
          setTimeout(() => sendInput(command), 500);
        });
      } else {
        sendInput(command);
      }
    }
  };

  const handleQuickCommand = (cmd: string) => {
    if (!sessionId) {
      setCommand(cmd);
      openSession().then(() => {
        setTimeout(() => sendInput(cmd), 500);
      });
    } else {
      sendInput(cmd);
    }
  };

  const combinedOutput = output.join('');

  return (
    <div className={`flex flex-col ${embedded ? 'h-full' : 'h-[500px]'} bg-[#0A0E1A] border border-slate-800/60 rounded-lg overflow-hidden`}>
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800/40 bg-[#0B0F1A] flex-shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={14} className={sessionId ? 'text-emerald-400' : 'text-slate-500'} />
          <span className="text-[12px] font-semibold text-slate-200">交互 Shell</span>
          {endpointName && (
            <>
              <ChevronRight size={10} className="text-slate-600" />
              <span className="text-[11px] text-slate-400 font-mono">{endpointName}</span>
            </>
          )}
          {sessionId && (
            <span className="text-[9px] text-slate-600 font-mono ml-1">sid:{sessionId.slice(-8)}</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {sessionId && (
            <span className={`flex items-center gap-1 text-[9px] ${connected ? 'text-emerald-500' : 'text-yellow-500'}`}>
              {connected ? <Wifi size={10} /> : <WifiOff size={10} />}
              {connected ? '已连接' : '重连中'}
            </span>
          )}
          {sessionId ? (
            <button onClick={closeSession} className="p-1.5 rounded text-red-400 hover:text-red-300 hover:bg-red-500/10" title="关闭会话">
              <Power size={12} />
            </button>
          ) : (
            <button onClick={openSession} disabled={opening} className="p-1.5 rounded text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40" title="打开会话">
              {opening ? <Loader2 size={12} className="animate-spin" /> : <Power size={12} />}
            </button>
          )}
          {onClose && <button onClick={onClose} className="p-1.5 rounded text-slate-500 hover:text-slate-300 hover:bg-slate-800/40"><X size={14} /></button>}
        </div>
      </div>

      <div ref={outputRef} className="flex-1 overflow-y-auto p-4 font-mono text-[12px] leading-relaxed">
        {!sessionId && !error && (
          <div className="text-slate-500 text-center py-8 text-[11px]">
            <Terminal size={24} className="mx-auto mb-2 opacity-20" />
            点击 <Power size={10} className="inline text-emerald-400" /> 打开交互式 Shell 会话<br />
            <span className="text-slate-600">支持 whoami / tasklist / netstat 等安全命令</span>
          </div>
        )}

        {error && (
          <div className="flex items-start gap-2 px-2.5 py-2 rounded bg-red-500/10 border border-red-500/30 mb-3">
            <AlertTriangle size={13} className="text-red-400 mt-0.5 flex-shrink-0" />
            <span className="text-[11px] text-red-400">{error}</span>
          </div>
        )}

        {sessionId && combinedOutput.length === 0 && (
          <div className="text-slate-600 text-center py-4 text-[11px]">
            <Loader2 size={14} className="mx-auto mb-1 animate-spin opacity-50" />
            等待 Shell 输出...
          </div>
        )}

        {combinedOutput.length > 0 && (
          <pre className="text-[11px] text-slate-300 whitespace-pre-wrap break-all">
            {combinedOutput}
          </pre>
        )}
      </div>

      <div className="border-t border-slate-800/40 bg-[#0B0F1A] flex-shrink-0">
        <div className="flex items-center gap-1.5 px-3 py-2 border-b border-slate-800/20 overflow-x-auto">
          {QUICK_COMMANDS.map((qc) => (
            <button
              key={qc}
              onClick={() => handleQuickCommand(qc)}
              disabled={sending}
              className="px-2.5 py-1 rounded text-[10px] text-slate-400 bg-slate-800/40 border border-slate-700/50 hover:bg-slate-700/60 hover:text-slate-200 transition-colors whitespace-nowrap flex-shrink-0 disabled:opacity-40"
            >
              {qc}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 px-3 py-2">
          <span className="text-emerald-400 text-[11px] font-semibold font-mono flex-shrink-0">PS&gt;</span>
          <input
            ref={inputRef}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={sessionId ? '输入命令...' : '点击电源按钮打开会话'}
            disabled={!sessionId || sending}
            className="flex-1 bg-transparent border-none outline-none text-[12px] text-slate-200 font-mono placeholder:text-slate-600 disabled:opacity-40"
          />
          <button
            onClick={() => sendInput(command)}
            disabled={!sessionId || sending || !command.trim()}
            className="p-1.5 rounded text-slate-400 hover:text-emerald-400 hover:bg-slate-800/60 disabled:opacity-30 transition-colors"
          >
            {sending ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
          </button>
        </div>
      </div>
    </div>
  );
}
