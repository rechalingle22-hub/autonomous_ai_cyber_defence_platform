import React, { useState } from 'react';
import { ResponseAction, Playbook, SOARStats } from '../types';
import { api } from '../services/api';
import {
  ShieldCheck,
  ShieldX,
  RotateCcw,
  Play,
  Clock,
  Workflow,
  CheckCircle,
} from 'lucide-react';

interface SoarApprovalViewProps {
  actions: ResponseAction[];
  playbooks: Playbook[];
  stats: SOARStats | null;
  onRefresh: () => void;
}

export const SoarApprovalView: React.FC<SoarApprovalViewProps> = ({
  actions,
  playbooks,
  stats,
  onRefresh,
}) => {
  const [selectedActionFilter, setSelectedActionFilter] = useState<string>('ALL');
  const [runningPlaybookId, setRunningPlaybookId] = useState<string | null>(null);
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  const pendingActions = actions.filter((a) => a.status === 'PENDING_APPROVAL');

  const filteredActions = actions.filter((a) => {
    if (selectedActionFilter === 'ALL') return true;
    return a.status === selectedActionFilter;
  });

  const handleApprove = async (actionId: string) => {
    await api.approveAction(actionId);
    setFeedbackMsg(`Action ${actionId} approved and executed.`);
    setTimeout(() => setFeedbackMsg(null), 4000);
    onRefresh();
  };

  const handleReject = async (actionId: string) => {
    await api.rejectAction(actionId);
    setFeedbackMsg(`Action ${actionId} rejected.`);
    setTimeout(() => setFeedbackMsg(null), 4000);
    onRefresh();
  };

  const handleRollback = async (actionId: string) => {
    await api.rollbackAction(actionId);
    setFeedbackMsg(`Rollback executed for action ${actionId}.`);
    setTimeout(() => setFeedbackMsg(null), 4000);
    onRefresh();
  };

  const handleTriggerPlaybook = async (playbookId: string) => {
    setRunningPlaybookId(playbookId);
    try {
      await api.executePlaybook(playbookId, 'INC-SOC-MANUAL-01', true);
      setFeedbackMsg(`Playbook ${playbookId} executed successfully (Simulation Mode).`);
      setTimeout(() => setFeedbackMsg(null), 4000);
      onRefresh();
    } finally {
      setRunningPlaybookId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Toast Feedback */}
      {feedbackMsg && (
        <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono flex items-center space-x-2">
          <CheckCircle className="w-4 h-4" />
          <span>{feedbackMsg}</span>
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-mono text-slate-400">PENDING AUTHORIZATION</div>
          <div className="text-2xl font-bold font-mono text-yellow-400 mt-1">
            {pendingActions.length}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-mono text-slate-400">EXECUTED CONTAINMENTS</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {stats?.executed_count ?? 0}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-mono text-slate-400">REGISTERED PLAYBOOKS</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {playbooks.length}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-mono text-slate-400">SAFETY WHITEGUARD</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">ACTIVE</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Actions List (Left Column) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              Response Actions & HITL Authorization Queue
            </h3>
            <div className="flex space-x-1">
              {['ALL', 'PENDING_APPROVAL', 'EXECUTED', 'ROLLED_BACK'].map((status) => (
                <button
                  key={status}
                  onClick={() => setSelectedActionFilter(status)}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono transition ${
                    selectedActionFilter === status
                      ? 'bg-slate-700 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {status.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          {filteredActions.length === 0 ? (
            <div className="p-12 rounded-xl bg-slate-900/60 border border-slate-800 text-center font-mono text-xs text-slate-400">
              No actions matching current filter.
            </div>
          ) : (
            filteredActions.map((action) => {
              const isPending = action.status === 'PENDING_APPROVAL';
              return (
                <div
                  key={action.id}
                  className={`p-4 rounded-xl border transition ${
                    isPending
                      ? 'bg-yellow-500/5 border-yellow-500/30'
                      : 'bg-slate-900/80 border-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold text-cyan-400">
                          {action.action_type}
                        </span>
                        <span
                          className={`px-2 py-0.2 rounded text-[10px] font-mono font-semibold ${
                            isPending
                              ? 'bg-yellow-500/20 text-yellow-300'
                              : action.status === 'EXECUTED'
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {action.status}
                        </span>
                      </div>

                      <div className="text-xs font-mono text-slate-200 mt-1">
                        TARGET: <span className="font-bold text-slate-100">{action.target_entity}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">{action.rationale}</div>
                    </div>

                    <div className="text-right text-xs font-mono">
                      <div className="text-slate-400">
                        RISK: <span className="font-bold text-orange-400">{action.risk_impact_score}</span>
                      </div>
                      <div className="text-slate-500 text-[10px] mt-1">
                        {new Date(action.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>

                  {/* Actions Bar */}
                  <div className="flex items-center justify-end space-x-2 mt-3 pt-3 border-t border-slate-800/80">
                    {isPending ? (
                      <>
                        <button
                          onClick={() => handleReject(action.id)}
                          className="px-3 py-1 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 hover:bg-rose-500/25 text-xs font-mono flex items-center space-x-1"
                        >
                          <ShieldX className="w-3 h-3" />
                          <span>Reject</span>
                        </button>
                        <button
                          onClick={() => handleApprove(action.id)}
                          className="px-3 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 text-xs font-mono font-bold flex items-center space-x-1"
                        >
                          <ShieldCheck className="w-3 h-3" />
                          <span>Authorize & Execute</span>
                        </button>
                      </>
                    ) : action.status === 'EXECUTED' ? (
                      <button
                        onClick={() => handleRollback(action.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 text-xs font-mono flex items-center space-x-1"
                      >
                        <RotateCcw className="w-3 h-3" />
                        <span>Compensate & Rollback</span>
                      </button>
                    ) : null}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Playbook Launcher (Right Column) */}
        <div className="lg:col-span-5 space-y-4">
          <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
            Declarative Response Playbooks
          </h3>

          <div className="space-y-3">
            {playbooks.map((pb) => (
              <div
                key={pb.playbook_id}
                className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-sm font-bold text-slate-100">{pb.name}</div>
                    <span className="text-[11px] font-mono text-cyan-400">{pb.playbook_id}</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                    {pb.steps.length} STEPS
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">{pb.description}</p>

                <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                  <div className="text-[11px] font-mono text-slate-500">
                    Triggers: {JSON.stringify(pb.trigger_criteria)}
                  </div>
                  <button
                    disabled={runningPlaybookId === pb.playbook_id}
                    onClick={() => handleTriggerPlaybook(pb.playbook_id)}
                    className="px-2.5 py-1 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/25 text-xs font-mono flex items-center space-x-1 font-semibold disabled:opacity-50"
                  >
                    <Play className="w-3 h-3" />
                    <span>{runningPlaybookId === pb.playbook_id ? 'Running...' : 'Trigger'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

