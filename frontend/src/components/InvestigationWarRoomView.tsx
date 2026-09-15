import React, { useState } from 'react';
import { Investigation, EvidenceItem, HypothesisItem } from '../types';
import { api } from '../services/api';
import {
  ShieldAlert,
  Brain,
  FileText,
  UserCheck,
  Search,
  PlusCircle,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';

interface InvestigationWarRoomViewProps {
  investigations: Investigation[];
  onRefresh: () => void;
}

export const InvestigationWarRoomView: React.FC<InvestigationWarRoomViewProps> = ({
  investigations,
  onRefresh,
}) => {
  const [selectedInv, setSelectedInv] = useState<Investigation | null>(
    investigations[0] || null
  );
  const [activeTab, setActiveTab] = useState<'evidence' | 'hypotheses' | 'scratchpad' | 'report'>('report');
  const [newClaim, setNewClaim] = useState('');
  const [newRisk, setNewRisk] = useState('HIGH');
  const [submittingHyp, setSubmittingHyp] = useState(false);

  const handleAddHypothesis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedInv || !newClaim.trim()) return;

    setSubmittingHyp(true);
    try {
      const res = await fetch(`/api/v1/investigations/${selectedInv.id}/hypothesize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          claim: newClaim.trim(),
          confidence: 0.85,
          risk_level: newRisk,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedInv(updated);
        setNewClaim('');
        onRefresh();
      }
    } finally {
      setSubmittingHyp(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Investigation List (Left Column) */}
      <div className="lg:col-span-4 space-y-3">
        <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
          Multi-Agent Investigation Cases ({investigations.length})
        </h3>

        {investigations.length === 0 ? (
          <div className="p-8 rounded-xl bg-slate-900/60 border border-dashed border-slate-800 text-center font-mono text-xs text-slate-400">
            No investigations triggered yet. Launch an AI investigation from the Incidents view.
          </div>
        ) : (
          investigations.map((inv) => {
            const isSelected = selectedInv?.id === inv.id;
            return (
              <div
                key={inv.id}
                onClick={() => setSelectedInv(inv)}
                className={`p-4 rounded-xl cursor-pointer transition border ${
                  isSelected
                    ? 'bg-slate-800/90 border-cyan-500/50 shadow-md shadow-cyan-500/5'
                    : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyan-400 font-bold">{inv.id}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                      inv.status === 'COMPLETED'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'bg-yellow-500/20 text-yellow-300'
                    }`}
                  >
                    {inv.status}
                  </span>
                </div>

                <div className="text-xs text-slate-200 mt-1 font-mono">
                  TARGET INCIDENT: <span className="font-bold">{inv.incident_id}</span>
                </div>

                <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-400">
                  <span>FP PROB: {((inv.false_positive_probability ?? 0.05) * 100).toFixed(1)}%</span>
                  <span>{new Date(inv.created_at).toLocaleTimeString()}</span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Case Dossier View (Right Column) */}
      <div className="lg:col-span-8 space-y-4">
        {selectedInv ? (
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
            {/* Header info */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-bold text-slate-100">Case: {selectedInv.id}</span>
                  <span className="text-xs font-mono text-slate-400">
                    (Incident: {selectedInv.incident_id})
                  </span>
                </div>
                {selectedInv.recommended_playbook && (
                  <div className="text-xs font-mono text-cyan-400 mt-1">
                    RECOMMENDED PLAYBOOK: <span className="font-bold">{selectedInv.recommended_playbook}</span>
                  </div>
                )}
              </div>

              {/* Sub-tabs */}
              <div className="flex space-x-1 bg-slate-800/80 p-1 rounded-lg">
                {[
                  { id: 'report', label: 'Dossier Report', icon: FileText },
                  { id: 'evidence', label: 'Observed Evidence', icon: ShieldCheck },
                  { id: 'hypotheses', label: 'Grounded Hypotheses', icon: Brain },
                  { id: 'scratchpad', label: 'Agent Scratchpad', icon: UserCheck },
                ].map((tab) => {
                  const Icon = tab.icon;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as any)}
                      className={`px-2.5 py-1 text-xs font-mono rounded flex items-center space-x-1.5 transition ${
                        activeTab === tab.id
                          ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Icon className="w-3 h-3" />
                      <span className="hidden sm:inline">{tab.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Dossier Report Tab */}
            {activeTab === 'report' && (
              <div className="space-y-4">
                {selectedInv.executive_summary && (
                  <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 space-y-2">
                    <div className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                      CISO Executive Summary
                    </div>
                    <p className="text-xs text-slate-300 font-mono leading-relaxed">
                      {selectedInv.executive_summary}
                    </p>
                  </div>
                )}

                {selectedInv.technical_analysis && (
                  <div className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 space-y-2">
                    <div className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                      Technical Forensic Analysis
                    </div>
                    <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed overflow-x-auto">
                      {selectedInv.technical_analysis}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* Observed Evidence Tab */}
            {activeTab === 'evidence' && (
              <div className="space-y-3">
                <div className="text-xs font-mono text-slate-400 mb-2">
                  Verified Ground-Truth Evidence (Isolated from Inferences):
                </div>
                {(selectedInv.observed_evidence?.items || []).length === 0 ? (
                  <div className="p-6 rounded-lg bg-slate-800/40 text-center font-mono text-xs text-slate-400">
                    No discrete evidence records stored.
                  </div>
                ) : (
                  selectedInv.observed_evidence.items?.map((ev: EvidenceItem) => (
                    <div
                      key={ev.evidence_id}
                      className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs font-mono space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-400">{ev.evidence_id}</span>
                        <span className="px-1.5 py-0.2 rounded bg-slate-700 text-slate-300 text-[10px]">
                          {ev.source} &bull; {ev.entity_type}
                        </span>
                      </div>
                      <div className="text-slate-100">
                        VALUE: <span className="text-slate-300">{ev.entity_value}</span>
                      </div>
                      <div className="text-slate-400 text-[11px]">{ev.description}</div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Grounded Hypotheses Tab */}
            {activeTab === 'hypotheses' && (
              <div className="space-y-4">
                <div className="space-y-3">
                  {(selectedInv.inferred_hypotheses?.items || []).map((hyp: HypothesisItem) => (
                    <div
                      key={hyp.hypothesis_id}
                      className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs font-mono space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-rose-400">{hyp.hypothesis_id}</span>
                        <span className="text-slate-400 text-[11px]">
                          CONFIDENCE: {(hyp.confidence * 100).toFixed(0)}% | RISK: {hyp.risk_level}
                        </span>
                      </div>
                      <div className="text-slate-100 font-medium">{hyp.claim}</div>
                      <div className="text-[11px] text-cyan-400">
                        SUPPORTING EVIDENCE: {hyp.supporting_evidence_ids.join(', ') || 'Analyst asserted'}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Add Custom Analyst Hypothesis Form */}
                <form
                  onSubmit={handleAddHypothesis}
                  className="p-4 rounded-xl bg-slate-800/40 border border-slate-700/60 space-y-3"
                >
                  <div className="text-xs font-mono font-bold text-slate-300 flex items-center space-x-1.5">
                    <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Augment Case with Human Analyst Hypothesis</span>
                  </div>

                  <input
                    type="text"
                    placeholder="Enter verifiable threat hypothesis..."
                    value={newClaim}
                    onChange={(e) => setNewClaim(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  />

                  <div className="flex items-center justify-between">
                    <select
                      value={newRisk}
                      onChange={(e) => setNewRisk(e.target.value)}
                      className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300"
                    >
                      <option value="CRITICAL">Risk: CRITICAL</option>
                      <option value="HIGH">Risk: HIGH</option>
                      <option value="MEDIUM">Risk: MEDIUM</option>
                      <option value="LOW">Risk: LOW</option>
                    </select>

                    <button
                      type="submit"
                      disabled={submittingHyp || !newClaim.trim()}
                      className="px-3 py-1 rounded-lg bg-cyan-500 text-slate-950 text-xs font-mono font-bold hover:bg-cyan-400 transition disabled:opacity-50"
                    >
                      {submittingHyp ? 'Recording...' : 'Record Hypothesis'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Scratchpad Tab */}
            {activeTab === 'scratchpad' && (
              <div className="space-y-4">
                {Object.entries(selectedInv.agent_scratchpad || {}).map(([agentKey, entries]) => (
                  <div
                    key={agentKey}
                    className="p-3 rounded-xl bg-slate-800/40 border border-slate-700/60 space-y-2"
                  >
                    <div className="text-xs font-mono font-bold text-cyan-400 uppercase">
                      Agent: {agentKey.replace('_', ' ')}
                    </div>
                    <div className="space-y-2">
                      {(entries || []).map((entry, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono space-y-1"
                        >
                          <div className="text-slate-400 text-[10px]">
                            ACTION: <span className="text-slate-200 font-bold">{entry.action_taken}</span>
                          </div>
                          <div className="text-slate-300 italic">&ldquo;{entry.thought_process}&rdquo;</div>
                          <div className="text-[11px] text-slate-400">
                            OBSERVATIONS: {entry.observations}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="p-16 rounded-xl bg-slate-900/40 border border-slate-800 text-center font-mono text-xs text-slate-400">
            Select an investigation case on the left to inspect multi-agent reasoning.
          </div>
        )}
      </div>
    </div>
  );
};

