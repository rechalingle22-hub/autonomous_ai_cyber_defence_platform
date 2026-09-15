import React, { useState, useEffect } from 'react';
import { Incident, AttackTimeline } from '../types';
import { api } from '../services/api';
import {
  ShieldAlert,
  ChevronRight,
  Clock,
  Crosshair,
  AlertCircle,
  Play,
} from 'lucide-react';

interface IncidentsTimelineViewProps {
  incidents: Incident[];
  onTriggerInvestigation: (incidentId: string) => void;
}

export const IncidentsTimelineView: React.FC<IncidentsTimelineViewProps> = ({
  incidents,
  onTriggerInvestigation,
}) => {
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<AttackTimeline[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState(false);

  useEffect(() => {
    if (incidents.length > 0 && !selectedIncident) {
      handleSelectIncident(incidents[0]);
    }
  }, [incidents]);

  const handleSelectIncident = async (inc: Incident) => {
    setSelectedIncident(inc);
    setLoadingTimeline(true);
    const data = await api.getIncidentTimeline(inc.id);
    setTimeline(data);
    setLoadingTimeline(false);
  };

  const stages = [
    'RECONNAISSANCE',
    'INITIAL_ACCESS',
    'EXECUTION',
    'LATERAL_MOVEMENT',
    'EXFILTRATION',
    'IMPACT',
  ];

  const getStageIndex = (stage: string) => {
    return stages.indexOf(stage.toUpperCase());
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Incident Selector List */}
      <div className="lg:col-span-5 space-y-3">
        <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
          <span>Active Correlated Incidents ({incidents.length})</span>
        </h3>

        {incidents.length === 0 ? (
          <div className="p-8 rounded-xl bg-slate-900/60 border border-dashed border-slate-800 text-center text-xs font-mono text-slate-400">
            No security incidents formed yet. Run a scenario from the Cyber Range to correlate alerts.
          </div>
        ) : (
          incidents.map((inc) => {
            const isSelected = selectedIncident?.id === inc.id;
            return (
              <div
                key={inc.id}
                onClick={() => handleSelectIncident(inc)}
                className={`p-4 rounded-xl cursor-pointer transition border ${
                  isSelected
                    ? 'bg-slate-800/90 border-cyan-500/50 shadow-md shadow-cyan-500/5'
                    : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-cyan-400">{inc.id}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      inc.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400'
                        : inc.severity === 'HIGH'
                        ? 'bg-orange-500/20 text-orange-400'
                        : 'bg-yellow-500/20 text-yellow-400'
                    }`}
                  >
                    {inc.severity}
                  </span>
                </div>

                <div className="font-medium text-sm text-slate-100 mt-1">{inc.title}</div>

                <div className="flex items-center justify-between mt-3 text-xs font-mono text-slate-400">
                  <div className="flex items-center space-x-1">
                    <span>RISK:</span>
                    <span
                      className={`font-bold ${
                        inc.composite_risk_score >= 75
                          ? 'text-rose-400'
                          : inc.composite_risk_score >= 50
                          ? 'text-orange-400'
                          : 'text-yellow-400'
                      }`}
                    >
                      {inc.composite_risk_score.toFixed(1)}/100
                    </span>
                  </div>
                  <span>STAGE: {inc.attack_stage}</span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Incident Detail & Attack Timeline */}
      <div className="lg:col-span-7 space-y-4">
        {selectedIncident ? (
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-5">
            {/* Header info */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-base font-bold text-slate-100">{selectedIncident.title}</h2>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                    {selectedIncident.id}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Created at: {new Date(selectedIncident.created_at).toLocaleString()}
                </p>
              </div>

              <button
                onClick={() => onTriggerInvestigation(selectedIncident.id)}
                className="px-3 py-1.5 rounded-lg bg-cyan-500 text-slate-950 hover:bg-cyan-400 font-mono text-xs font-bold transition flex items-center space-x-1.5 shadow-sm shadow-cyan-500/20 whitespace-nowrap"
              >
                <Play className="w-3.5 h-3.5 fill-slate-950" />
                <span>Launch AI Investigation &rarr;</span>
              </button>
            </div>

            {/* MITRE Cyber Kill-Chain Progression */}
            <div>
              <div className="text-xs font-mono font-bold text-slate-400 mb-2 uppercase tracking-wider">
                MITRE ATT&CK Kill-Chain Progression
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-6 gap-1.5">
                {stages.map((stg, i) => {
                  const currentIdx = getStageIndex(selectedIncident.attack_stage);
                  const isReached = currentIdx >= i;
                  const isCurrent = currentIdx === i;
                  return (
                    <div
                      key={stg}
                      className={`p-2 rounded text-center font-mono text-[10px] font-semibold border transition ${
                        isCurrent
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/60 ring-1 ring-rose-500/30'
                          : isReached
                          ? 'bg-orange-500/10 text-orange-300 border-orange-500/30'
                          : 'bg-slate-800/40 text-slate-500 border-slate-800'
                      }`}
                    >
                      <div className="text-[9px] text-slate-400">0{i + 1}</div>
                      <div className="truncate">{stg.replace('_', ' ')}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Chronological Attack Timeline */}
            <div>
              <div className="text-xs font-mono font-bold text-slate-400 mb-3 uppercase tracking-wider flex items-center space-x-1.5">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>Chronological Attack Progression Timeline</span>
              </div>

              {loadingTimeline ? (
                <div className="text-xs font-mono text-slate-400 py-6 text-center">
                  Loading incident attack timeline...
                </div>
              ) : timeline.length === 0 ? (
                <div className="p-4 rounded-lg bg-slate-800/40 text-center text-xs font-mono text-slate-400">
                  No discrete timeline points recorded yet.
                </div>
              ) : (
                <div className="space-y-3 relative pl-4 border-l border-slate-800">
                  {timeline.map((item, idx) => (
                    <div key={item.id || idx} className="relative">
                      {/* Timeline dot */}
                      <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-900" />

                      <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs font-mono">
                        <div className="flex items-center justify-between text-slate-400 text-[11px] mb-1">
                          <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                          {item.mitre_technique && (
                            <span className="text-cyan-400 font-bold">{item.mitre_technique}</span>
                          )}
                        </div>
                        <div className="text-slate-100 font-medium">{item.event_summary}</div>
                        <div className="text-slate-400 text-[11px] mt-1">
                          ENTITY: <span className="text-slate-200">{item.entity}</span> | SOURCE:{' '}
                          <span className="text-slate-300">{item.detection_source}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="p-12 rounded-xl bg-slate-900/40 border border-slate-800 text-center text-slate-400 font-mono text-xs">
            Select an incident on the left to inspect kill-chain timeline.
          </div>
        )}
      </div>
    </div>
  );
};

