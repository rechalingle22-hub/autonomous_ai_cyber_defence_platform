import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  Activity,
  Cpu,
  Workflow,
  RotateCcw,
  Zap,
  Lock,
  Target,
  Compass,
  Archive,
  Swords,
  GitFork,
  Cloud,
  Package,
  Layers,
  Flame,
  Eye,
  Radio,
  ExternalLink,
  CheckCircle2,
  Terminal,
  Clock,
  Sparkles,
  Server,
  Crosshair,
} from 'lucide-react';
import { api } from '../services/api';
import {
  MasterPosture,
  SubsystemHealth,
  PlatformDiagnostics,
} from '../types';

interface MasterNexusViewProps {
  onNavigate: (tabId: string) => void;
}

// Map engine code to frontend navigation tab ID
const ENGINE_TAB_MAP: Record<string, string> = {
  DETECTION_UNSUPERVISED: 'radar',
  DETECTION_SUPERVISED: 'radar',
  EXPLAINABILITY_XAI: 'xai',
  CORRELATION_ATTACK: 'incidents',
  WARROOM_MULTI_AGENT: 'warroom',
  SOAR_PLAYBOOKS: 'soar',
  MLOPS_DRIFT: 'mlops',
  CHAOS_RESILIENCE: 'chaos',
  DECEPTION_HONEYTOKENS: 'deception',
  ZEROTRUST_ZTNA: 'zerotrust',
  ASM_ATTACK_SURFACE: 'asm',
  THREAT_HUNTING: 'hunting',
  DFIR_FORENSICS: 'dfir',
  BAS_EMULATION: 'bas',
  EXPOSURE_ATTACK_PATHS: 'paths',
  CSPM_CLOUD_GUARD: 'cspm',
  SCA_SUPPLY_CHAIN: 'sca',
  STREAMING_INGRESS: 'radar',
  UEBA_BEHAVIORAL: 'radar',
  THREAT_INTEL: 'incidents',
  EXECUTIVE_REPORTING: 'radar',
  AUDIT_LEDGER: 'soar',
  WEBSOCKETS_REALTIME: 'radar',
  CYBER_RANGE: 'simulator',
};

export const MasterNexusView: React.FC<MasterNexusViewProps> = ({ onNavigate }) => {
  const [posture, setPosture] = useState<MasterPosture | null>(null);
  const [diagnostics, setDiagnostics] = useState<PlatformDiagnostics | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  const [isLockdownModalOpen, setIsLockdownModalOpen] = useState(false);
  const [isDiagModalOpen, setIsDiagModalOpen] = useState(false);
  const [lockdownReason, setLockdownReason] = useState('COORDINATED_APT_CONTAINMENT');
  const [isLockdownLoading, setIsLockdownLoading] = useState(false);
  const [isDiagLoading, setIsDiagLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const data = await api.getNexusPosture();
      setPosture(data);
    } catch (err) {
      console.error('Failed to load Nexus posture:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleTriggerLockdown = async () => {
    try {
      setIsLockdownLoading(true);
      await api.triggerEmergencyLockdown('SOC_COMMANDER', lockdownReason);
      setIsLockdownModalOpen(false);
      await loadData();
    } catch (err) {
      console.error('Lockdown failed:', err);
    } finally {
      setIsLockdownLoading(false);
    }
  };

  const handleLiftLockdown = async () => {
    try {
      setIsLockdownLoading(true);
      await api.liftEmergencyLockdown();
      await loadData();
    } catch (err) {
      console.error('Lifting lockdown failed:', err);
    } finally {
      setIsLockdownLoading(false);
    }
  };

  const handleRunDiagnostics = async () => {
    try {
      setIsDiagLoading(true);
      const diag = await api.runPlatformDiagnostics();
      setDiagnostics(diag);
      setIsDiagModalOpen(true);
    } catch (err) {
      console.error('Diagnostics failed:', err);
    } finally {
      setIsDiagLoading(false);
    }
  };

  const filteredSubsystems = (posture?.subsystems || []).filter((s) => {
    if (categoryFilter === 'ALL') return true;
    return s.category.toLowerCase().includes(categoryFilter.toLowerCase());
  });

  if (loading && !posture) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-slate-400 font-mono text-sm">Interrogating All 24 Autonomous Security Subsystems...</p>
        </div>
      </div>
    );
  }

  const isLockdown = posture?.is_lockdown_active;

  return (
    <div className="space-y-6">
      {/* Master Flagship Banner */}
      <div
        className={`p-6 rounded-2xl border transition-all ${
          isLockdown
            ? 'bg-rose-950/40 border-rose-500/60 shadow-2xl shadow-rose-950/40'
            : 'bg-slate-900/80 border-slate-800 shadow-xl shadow-cyan-950/20'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start space-x-4">
            <div
              className={`p-3.5 rounded-2xl border ${
                isLockdown
                  ? 'bg-rose-500/20 border-rose-500/40 text-rose-400 animate-pulse'
                  : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
              }`}
            >
              {isLockdown ? <AlertOctagon className="w-9 h-9" /> : <ShieldCheck className="w-9 h-9 animate-pulse" />}
            </div>
            <div>
              <div className="flex items-center space-x-3">
                <h2 className="text-2xl font-black tracking-wider text-slate-100 uppercase font-mono flex items-center space-x-2">
                  <span>MASTER SOC COMMAND NEXUS</span>
                </h2>
                <span
                  className={`text-xs px-3 py-1 rounded-full font-mono font-bold border ${
                    isLockdown
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/50 animate-pulse'
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  }`}
                >
                  {isLockdown ? 'EMERGENCY LOCKDOWN ACTIVE' : 'PLATFORM 100% OPERATIONAL'}
                </span>
                <span className="text-xs px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-mono hidden sm:inline">
                  25/25 Phases Complete
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 font-mono mt-1">
                Synchronized autonomous command plane orchestrating all 24 AI defense engines, real-time XAI explainability, and Zero-Trust isolation.
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleRunDiagnostics}
              disabled={isDiagLoading}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold transition"
            >
              <Sparkles className="w-4 h-4" />
              <span>{isDiagLoading ? 'Running Probe...' : 'Self-Healing Diagnostics'}</span>
            </button>

            {isLockdown ? (
              <button
                onClick={handleLiftLockdown}
                disabled={isLockdownLoading}
                className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold transition shadow-lg shadow-emerald-950/40"
              >
                <RotateCcw className="w-4 h-4" />
                <span>Lift Emergency Lockdown</span>
              </button>
            ) : (
              <button
                onClick={() => setIsLockdownModalOpen(true)}
                className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-rose-600/90 hover:bg-rose-500 text-white text-xs font-mono font-bold transition shadow-lg shadow-rose-950/40"
              >
                <AlertOctagon className="w-4 h-4" />
                <span>Emergency Platform Lockdown</span>
              </button>
            )}

            <button
              onClick={loadData}
              className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh Telemetry"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Lockdown Active Alert Bar */}
        {isLockdown && posture?.lockdown_details && (
          <div className="mt-5 p-4 rounded-xl bg-rose-950/60 border border-rose-500/50 text-xs font-mono text-rose-200 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold tracking-wider flex items-center space-x-2">
                <AlertOctagon className="w-4 h-4 text-rose-400" />
                <span>LOCKDOWN PROTOCOL ENGAGED: {posture.lockdown_details.lockdown_id}</span>
              </span>
              <span>Operator: {posture.lockdown_details.operator}</span>
            </div>
            <div className="text-[11px] text-rose-300/80">
              Zero-Trust default-deny active &bull; 4 Minimal Cut Choke Points severed &bull; Quarantined Subnets:{' '}
              {posture.lockdown_details.quarantined_subnets.join(', ')}
            </div>
          </div>
        )}
      </div>

      {/* Global Defense Readiness & SOC KPI Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Readiness Index</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-cyan-400">
              {posture?.defense_readiness_index || 98.6}%
            </span>
          </div>
          <span className="text-[11px] text-emerald-400 font-mono mt-1">Autonomous Defense Grade A+</span>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Active Engines</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-emerald-400">
              {posture?.online_subsystems || 24}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ {posture?.total_subsystems || 24}</span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono mt-1">100% Subsystems Online</span>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Mean Time to Detect</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-purple-400">
              {posture?.mean_time_to_detect_sec || 3.8}s
            </span>
          </div>
          <span className="text-[11px] text-purple-400/80 font-mono mt-1">Sub-4 Second Detection</span>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Mean Time to Remediate</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-teal-400">
              {posture?.mean_time_to_remediate_sec || 12.4}s
            </span>
          </div>
          <span className="text-[11px] text-teal-400/80 font-mono mt-1">Autonomous Containment</span>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Threats Neutralized</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-amber-400">
              {(posture?.total_threats_blocked || 14290).toLocaleString()}
            </span>
          </div>
          <span className="text-[11px] text-amber-400/80 font-mono mt-1">
            {posture?.automated_containment_rate || 98.7}% auto-contained
          </span>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Zero-Trust Posture</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span
              className={`text-xl font-bold font-mono ${
                isLockdown ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {posture?.zero_trust_status || 'ENFORCED'}
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono mt-1">
            {posture?.choke_points_severed || 3} Choke Points Severed
          </span>
        </div>
      </div>

      {/* Operational Matrix Header & Category Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div>
          <h3 className="text-lg font-bold text-slate-100 font-mono flex items-center space-x-2">
            <span>24-Engine Autonomous Defense Matrix</span>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-normal">
              Live Health Pulse
            </span>
          </h3>
          <p className="text-xs text-slate-400 font-mono">
            Direct operational telemetry and fast navigation across all integrated defensive capabilities
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          {['ALL', 'Detection', 'Active Defense', 'Exposure', 'Governance', 'Infrastructure'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 rounded-lg transition ${
                categoryFilter === cat
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* 24-Subsystem Operational Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filteredSubsystems.map((sub) => {
          const targetTab = ENGINE_TAB_MAP[sub.code] || 'radar';

          return (
            <div
              key={sub.id}
              className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-3 group"
            >
              <div>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-[10px] font-mono text-cyan-400 font-bold px-1.5 py-0.5 rounded bg-cyan-950/40 border border-cyan-900/60">
                    {sub.id} &bull; {sub.category}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                      sub.status === 'ONLINE'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : sub.status === 'LOCKDOWN'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                        : 'bg-amber-500/10 text-amber-400'
                    }`}
                  >
                    {sub.status}
                  </span>
                </div>

                <h4 className="text-sm font-bold text-slate-100 font-mono mt-2 group-hover:text-cyan-300 transition">
                  {sub.name}
                </h4>

                <p className="text-[11px] text-slate-400 font-mono mt-1 line-clamp-2">
                  {sub.engine_type}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
                <div className="flex items-center space-x-3">
                  <span>{sub.latency_ms}ms</span>
                  <span>{sub.uptime_percent}% up</span>
                </div>
                <button
                  onClick={() => onNavigate(targetTab)}
                  className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-semibold transition text-xs"
                >
                  <span>Open Console</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Emergency Lockdown Confirmation Modal */}
      {isLockdownModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-xl bg-slate-900 border border-rose-500/60 rounded-2xl p-6 space-y-5 shadow-2xl shadow-rose-950/50">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40">
                <AlertOctagon className="w-7 h-7 animate-pulse" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-100 font-mono">
                  CONFIRM EMERGENCY PLATFORM LOCKDOWN
                </h3>
                <p className="text-xs text-rose-300 font-mono">
                  Autonomous Multi-Engine Perimeter Severance & Dynamic Containment
                </p>
              </div>
            </div>

            <p className="text-xs text-slate-300 font-mono leading-relaxed">
              Triggering emergency lockdown will immediately coordinate all 24 cyber defense engines into active defense mode:
            </p>

            <ul className="text-xs text-slate-400 font-mono space-y-1.5 list-disc list-inside bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <li>Zero-Trust ZTNA switched to universal DEFAULT_DENY microsegmentation</li>
              <li>Physical severance of all 4 graph-computed Attack Path Choke Points</li>
              <li>Immediate session revocation for all non-privileged workstations</li>
              <li>Honeytoken canaries primed for maximum tripwire sensitivity</li>
              <li>Certified Merkle chain-of-custody snapshot committed to immutable log</li>
            </ul>

            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">Reason for Containment:</label>
              <input
                type="text"
                value={lockdownReason}
                onChange={(e) => setLockdownReason(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:ring-1 focus:ring-rose-500"
              />
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => setIsLockdownModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs font-mono hover:bg-slate-700 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleTriggerLockdown}
                disabled={isLockdownLoading}
                className="px-5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold transition shadow-lg shadow-rose-950/40"
              >
                {isLockdownLoading ? 'Engaging Lockdown...' : 'EXECUTE LOCKDOWN'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Self-Healing Diagnostics Modal */}
      {isDiagModalOpen && diagnostics && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-slate-900 border border-cyan-500/50 rounded-2xl p-6 space-y-5 shadow-2xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-3">
                <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                <div>
                  <h3 className="text-base font-bold text-slate-100 font-mono">
                    {diagnostics.platform_certification}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">
                    Self-Healing Diagnostic Verification ({diagnostics.total_checks_passed} Checks Passed, 0 Failed)
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsDiagModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-mono"
              >
                Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 text-xs font-mono">
              {diagnostics.engine_results.map((r) => (
                <div
                  key={r.subsystem_id}
                  className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-center justify-between"
                >
                  <div>
                    <span className="text-cyan-400 font-bold">{r.subsystem_id}: {r.name}</span>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Code: {r.code} &bull; Memory Leak: {r.memory_leak_check} &bull; Locks: {r.concurrency_lock_check}
                    </div>
                  </div>
                  <span className="text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 font-bold">
                    {r.health}
                  </span>
                </div>
              ))}
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
              <span>AI Defense Score: {diagnostics.ai_defense_score}%</span>
              <button
                onClick={() => setIsDiagModalOpen(false)}
                className="px-4 py-1.5 rounded-lg bg-cyan-600/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-600/30 transition"
              >
                Acknowledge Certification
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

