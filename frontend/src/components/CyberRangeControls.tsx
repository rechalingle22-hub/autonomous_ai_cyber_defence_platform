import React, { useState } from 'react';
import { api } from '../services/api';
import { Crosshair, Play, CheckCircle2, AlertOctagon } from 'lucide-react';

interface CyberRangeControlsProps {
  onScenarioTriggered: () => void;
}

export const CyberRangeControls: React.FC<CyberRangeControlsProps> = ({ onScenarioTriggered }) => {
  const [activeScenarioId, setActiveScenarioId] = useState<number | null>(null);
  const [duration, setDuration] = useState(15);
  const [statusLog, setStatusLog] = useState<string[]>([]);

  const scenarios = [
    {
      id: 1,
      name: 'SSH Brute-Force Authentication Spike',
      description: 'Generates high-frequency failed SSH authentication bursts against port 22.',
      category: 'CREDENTIAL_ACCESS',
      severity: 'HIGH',
    },
    {
      id: 2,
      name: 'Horizontal Network Port Sweep',
      description: 'Scans across destination network ports with high Shannon entropy.',
      category: 'RECONNAISSANCE',
      severity: 'MEDIUM',
    },
    {
      id: 3,
      name: 'Bulk Data Exfiltration Stream',
      description: 'Transfers large forward packet volumes and high outbound-byte ratios to external C2.',
      category: 'EXFILTRATION',
      severity: 'CRITICAL',
    },
    {
      id: 4,
      name: 'Compromised Account Behavioral Deviation',
      description: 'Triggers abnormal out-of-hours user logins and anomalous database queries.',
      category: 'INSIDER_THREAT',
      severity: 'HIGH',
    },
    {
      id: 5,
      name: 'Multi-Stage Cyber Kill-Chain Campaign',
      description: 'Progresses through Recon -> Initial Access -> Lateral Movement -> Exfiltration.',
      category: 'CAMPAIGN',
      severity: 'CRITICAL',
    },
  ];

  const handleRunScenario = async (scenId: number, name: string) => {
    setActiveScenarioId(scenId);
    const logLine = `[${new Date().toLocaleTimeString()}] Dispatched Scenario #${scenId} ('${name}') for ${duration}s...`;
    setStatusLog((prev) => [logLine, ...prev.slice(0, 9)]);

    try {
      await api.runScenario(scenId, duration);
      const doneLine = `[${new Date().toLocaleTimeString()}] Scenario #${scenId} completed. Telemetry ingested, correlated, and dispatched to WebSocket.`;
      setStatusLog((prev) => [doneLine, ...prev.slice(0, 9)]);
      onScenarioTriggered();
    } catch (err) {
      const errLine = `[${new Date().toLocaleTimeString()}] Error running scenario #${scenId}: ${String(err)}`;
      setStatusLog((prev) => [errLine, ...prev.slice(0, 9)]);
    } finally {
      setActiveScenarioId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Configuration Bar */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-mono font-bold text-slate-100 flex items-center space-x-2">
            <Crosshair className="w-4 h-4 text-cyan-400" />
            <span>Cyber Range Synthetic Attack Generator</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Safely injects synthetic, realistic cyber threat scenarios to exercise the AI detection, correlation, and response pipelines.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono text-slate-300">
          <span>Duration:</span>
          <select
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
            className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-cyan-400 font-bold"
          >
            <option value={5}>5 seconds</option>
            <option value={15}>15 seconds</option>
            <option value={30}>30 seconds</option>
            <option value={60}>60 seconds</option>
          </select>
        </div>
      </div>

      {/* Scenarios Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((scen) => {
          const isRunning = activeScenarioId === scen.id;
          return (
            <div
              key={scen.id}
              className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between space-y-4 hover:border-slate-700 transition"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400">
                    SCENARIO #{scen.id}
                  </span>
                  <span
                    className={`px-2 py-0.2 rounded text-[10px] font-mono font-bold ${
                      scen.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400'
                        : scen.severity === 'HIGH'
                        ? 'bg-orange-500/20 text-orange-400'
                        : 'bg-yellow-500/20 text-yellow-400'
                    }`}
                  >
                    {scen.severity}
                  </span>
                </div>

                <div className="text-sm font-bold text-slate-100">{scen.name}</div>
                <p className="text-xs text-slate-400 leading-relaxed">{scen.description}</p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-500">{scen.category}</span>

                <button
                  disabled={isRunning}
                  onClick={() => handleRunScenario(scen.id, scen.name)}
                  className="px-3 py-1 rounded-lg bg-cyan-500 text-slate-950 font-mono text-xs font-bold hover:bg-cyan-400 transition flex items-center space-x-1.5 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-slate-950" />
                  <span>{isRunning ? 'Injecting...' : 'Inject Attack'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Simulator Execution Log */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
        <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
          Live Cyber Range Injection Log
        </div>
        <div className="p-3 rounded-lg bg-slate-950 font-mono text-xs text-slate-300 space-y-1 max-h-40 overflow-y-auto">
          {statusLog.length === 0 ? (
            <span className="text-slate-600">Ready. Click any &lsquo;Inject Attack&rsquo; button above to generate telemetry.</span>
          ) : (
            statusLog.map((line, i) => (
              <div key={i} className="text-cyan-400/90 leading-relaxed">
                {line}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

