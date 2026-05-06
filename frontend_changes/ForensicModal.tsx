import { useState, useCallback } from 'react';
import { Shield, Loader2, X, CheckCircle, AlertTriangle, FileSearch, HardDrive, Clock } from 'lucide-react';
import { apiClient } from '@/api/client';
import { unwrapResponseBody } from '@/api/envelope';

interface DeepForensicResponse {
  task_id: string;
  status: string;
  created_at: string;
}

interface ForensicModalProps {
  endpointId: string;
  endpointName?: string;
  isOpen: boolean;
  onClose: () => void;
}

const SCOPES = [
  { value: 1, label: '快速', desc: '进程列表、网络连接、启动项 (~30s)', icon: FileSearch },
  { value: 2, label: '标准', desc: '快速 + MFT、事件日志、服务 (~2min)', icon: HardDrive },
  { value: 3, label: '深度', desc: '标准 + 注册表、浏览器历史、Prefetch (~5min)', icon: Clock },
];

export default function ForensicModal({ endpointId, endpointName, isOpen, onClose }: ForensicModalProps) {
  const [scope, setScope] = useState(2);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ task_id: string; status: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submitForensic = useCallback(async () => {
    if (!endpointId || submitting) return;
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiClient.post<DeepForensicResponse>(
        `/endpoints/${encodeURIComponent(endpointId)}/forensic/deep`,
        {
          scope,
          reason: reason.trim() || '来自告警详情页的深度取证请求',
        },
      );
      const data = unwrapResponseBody<DeepForensicResponse>(res.data);
      setResult({ task_id: data.task_id, status: data.status });
    } catch (e) {
      setError(e instanceof Error ? e.message : '提交取证请求失败');
    } finally {
      setSubmitting(false);
    }
  }, [endpointId, scope, reason, submitting]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-[#0F1420] border border-slate-700/60 rounded-xl w-[500px] max-h-[85vh] shadow-2xl shadow-black/40 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800/60 bg-[#0B0F1A]">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-blue-400" />
            <span className="text-[13px] font-semibold text-slate-200">深度取证采集</span>
          </div>
          <button onClick={onClose} className="p-1 rounded text-slate-500 hover:text-slate-300 hover:bg-slate-800/40">
            <X size={16} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {endpointName && (
            <div className="text-[11px] text-slate-400">
              目标终端: <span className="text-slate-200 font-mono">{endpointName}</span>
              <span className="text-slate-600 ml-2">({endpointId})</span>
            </div>
          )}

          {!result && (
            <>
              <div className="space-y-2">
                <label className="text-[11px] font-medium text-slate-400">采集范围</label>
                <div className="space-y-2">
                  {SCOPES.map((s) => {
                    const Icon = s.icon;
                    return (
                      <button
                        key={s.value}
                        onClick={() => setScope(s.value)}
                        className={`w-full flex items-start gap-3 px-3.5 py-3 rounded-lg border text-left transition-colors ${
                          scope === s.value
                            ? 'border-blue-500/60 bg-blue-500/10 text-slate-200'
                            : 'border-slate-700/50 bg-slate-800/20 text-slate-400 hover:border-slate-600/60'
                        }`}
                      >
                        <Icon size={14} className="mt-0.5 flex-shrink-0" />
                        <div>
                          <div className="text-[12px] font-medium">{s.label}</div>
                          <div className="text-[10px] opacity-70 mt-0.5">{s.desc}</div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[11px] font-medium text-slate-400">取证原因 (可选)</label>
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="例如: 调查告警 ALERT-xxx 的横向移动行为"
                  className="w-full bg-slate-800/40 border border-slate-700/50 rounded-lg px-3 py-2.5 text-[12px] text-slate-200 placeholder:text-slate-600 outline-none focus:border-blue-500/60 transition-colors"
                />
              </div>

              {error && (
                <div className="flex items-start gap-2 px-3 py-2.5 rounded bg-red-500/10 border border-red-500/30">
                  <AlertTriangle size={13} className="text-red-400 mt-0.5 flex-shrink-0" />
                  <span className="text-[11px] text-red-400">{error}</span>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-1">
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-[12px] text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 transition-colors"
                >
                  取消
                </button>
                <button
                  onClick={submitForensic}
                  disabled={submitting}
                  className="px-5 py-2 rounded-lg text-[12px] font-medium bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50 transition-colors flex items-center gap-2"
                >
                  {submitting ? (
                    <><Loader2 size={13} className="animate-spin" /> 提交中...</>
                  ) : (
                    '开始采集'
                  )}
                </button>
              </div>
            </>
          )}

          {result && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                <CheckCircle size={18} className="text-emerald-400 flex-shrink-0" />
                <div>
                  <div className="text-[12px] font-medium text-emerald-400">取证任务已下发</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">
                    task_id: <span className="font-mono text-slate-300">{result.task_id}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    采集器将在终端后台运行，完成后可在取证结果面板查看。
                  </div>
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-[12px] bg-slate-800/60 hover:bg-slate-700/60 text-slate-300 transition-colors"
                >
                  关闭
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
