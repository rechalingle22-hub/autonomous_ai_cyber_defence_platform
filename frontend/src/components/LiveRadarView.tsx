import React, { useState } from 'react';
import { Alert, Severity } from '../types';
import { Shield, AlertTriangle, Radio, Search, Filter } from 'lucide-react';

interface LiveRadarViewProps {
  alerts: Alert[];
  onSelectAlertForXai?: (alert: Alert) => void;
}

export const LiveRadarView: React.FC<LiveRadarViewProps> = ({ alerts, onSelectAlertForXai }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const filteredAlerts = alerts.filter((a) => {
    const matchesSearch =
      a.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (a.source_ip && a.source_ip.includes(searchTerm)) ||
      (a.destination_ip && a.destination_ip.includes(searchTerm)) ||
      (a.attack_category && a.attack_category.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSeverity = selectedSeverity === 'ALL' || a.severity === selectedSeverity;
    return matchesSearch && matchesSeverity;
  });

  const criticalCount = alerts.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter((a) => a.severity === 'HIGH').length;
  const mediumCount = alerts.filter((a) => a.severity === 'MEDIUM').length;
  const lowCount = alerts.filter((a) => a.severity === 'LOW').length;

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-400 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40';
      default:
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/40';
    }
  };

  return (
    <div className="space-y-6">
      {/* Metric Cards Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">CRITICAL ALERTS</div>
            <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{criticalCount}</div>
          </div>
          <div className="p-3 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">HIGH SEVERITY</div>
            <div className="text-2xl font-bold font-mono text-orange-400 mt-1">{highCount}</div>
          </div>
          <div className="p-3 rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/20">
            <Shield className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">MEDIUM / ELEVATED</div>
            <div className="text-2xl font-bold font-mono text-yellow-400 mt-1">{mediumCount}</div>
          </div>
          <div className="p-3 rounded-lg bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
            <Radio className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">TOTAL STREAM EVENTS</div>
            <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{alerts.length}</div>
          </div>
          <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Radio className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IP, Technique, Category..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-1.5 overflow-x-auto w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-500 mr-1" />
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono transition ${
                selectedSeverity === sev
                  ? 'bg-slate-700 text-cyan-300 font-semibold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Stream List Cards */}
      <div className="space-y-2.5">
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-16 p-6 rounded-xl bg-slate-900/40 border border-dashed border-slate-800 text-slate-400 font-mono text-xs">
            No threat detections matching filter criteria. Live streaming radar listening on /ws/soc.
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition flex flex-col md:flex-row md:items-center md:justify-between gap-3"
            >
              <div className="flex items-start space-x-3">
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${getSeverityBadge(
                    alert.severity
                  )}`}
                >
                  {alert.severity}
                </span>

                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-medium text-slate-100">{alert.title}</span>
                    {alert.attack_category && (
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 text-[10px] font-mono">
                        {alert.attack_category}
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono mt-1">
                    {alert.source_ip && (
                      <span>
                        SRC: <span className="text-slate-200">{alert.source_ip}</span>
                        {alert.source_port ? `:${alert.source_port}` : ''}
                      </span>
                    )}
                    {alert.destination_ip && (
                      <span>
                        DST: <span className="text-slate-200">{alert.destination_ip}</span>
                        {alert.destination_port ? `:${alert.destination_port}` : ''}
                      </span>
                    )}
                    {alert.protocol && (
                      <span className="text-slate-400">PROTO: {alert.protocol}</span>
                    )}
                    {alert.confidence !== undefined && (
                      <span className="text-cyan-400">
                        CONF: {(alert.confidence * 100).toFixed(1)}%
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-3 self-end md:self-center">
                <span className="text-[11px] text-slate-500 font-mono whitespace-nowrap">
                  {new Date(alert.created_at).toLocaleTimeString()}
                </span>

                {onSelectAlertForXai && (
                  <button
                    onClick={() => onSelectAlertForXai(alert)}
                    className="px-2.5 py-1 text-xs font-mono rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition whitespace-nowrap"
                  >
                    Inspect XAI &rarr;
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

