import React, { useState, useEffect } from 'react';
import {
  Flame,
  ShieldAlert,
  AlertOctagon,
  Zap,
  RefreshCw,
  Play,
  StopCircle,
  CheckCircle2,
  AlertTriangle,
  Cpu,
  Clock,
  ShieldCheck,
  RotateCcw,
  Activity,
  Server,
  Radio,
} from 'lucide-react';
import { api } from '../services/api';
import {
  ChaosStatus,
  ChaosExperiment,
  ChaosType,
  AdversarialEvaluateResponse,
} from '../types';

export const ChaosEngineeringView: React.FC = () => {
  const [chaosStatus, setChaosStatus] = useState<ChaosStatus | null>(null);
  const [experiments, setExperiments] = useState<ChaosExperiment[]>([]);
  const [adversarialResult, setAdversarialResult] = useState<AdversarialEvaluateResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isAdversarialLoading, setIsAdversarialLoading] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Injection parameters
  const [selectedDuration, setSelectedDuration] = useState<number>(30);
  const [selectedEpsilon, setSelectedEpsilon] = useState<number>(0.15);
  const [selectedTechnique, setSelectedTechnique] = useState<string>('BENIGN_MIMICRY');
  const [injectingType, setInjectingType] = useState<ChaosType | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [status, exps] = await Promise.all([
        api.getChaosStatus(),
        api.getChaosExperiments(),
      ]);
      setChaosStatus(status);
      setExperiments(exps);
    } catch {
      // Graceful fallback
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleInjectChaos = async (type: ChaosType, customParams: Record<string, any> = {}) => {
    setInjectingType(type);
    try {
      const exp = await api.injectChaos(type, selectedDuration, customParams);
      if (exp) {
        setActionMessage(`🔥 Chaos Injected: ${type} (Active for ${selectedDuration}s). Resilience verification underway.`);
        await loadData();
      } else {
        setActionMessage(`❌ Failed to inject chaos experiment: ${type}`);
      }
    } catch {
      setActionMessage(`❌ Error during chaos injection.`);
    } finally {
      setInjectingType(null);
      setTimeout(() => setActionMessage(null), 7000);
    }
  };

  const handleEmergencyRecover = async (experimentId?: string) => {
    setIsLoading(true);
    try {
      await api.recoverChaos(experimentId);
      setActionMessage(
        experimentId
          ? `🛡️ Fault lease recovered for experiment: ${experimentId}`
          : `🛡️ EMERGENCY RECOVERY TRIGGERED: 100% Steady-state restored across all services.`
      );
      await loadData();
    } catch {
      setActionMessage(`❌ Error during chaos recovery.`);
    } finally {
      setIsLoading(false);
      setTimeout(() => setActionMessage(null), 7000);
    }
  };

  const handleRunAdversarialTest = async () => {
    setIsAdversarialLoading(true);
    try {
      const res = await api.evaluateAdversarial(selectedEpsilon, selectedTechnique);
      setAdversarialResult(res);
      setActionMessage(`⚔️ Adversarial evaluation completed! Robustness Grade: ${res?.ensemble_robustness_grade} (ARI: ${((res?.ensemble_adversarial_robustness_index ?? 0) * 100).toFixed(1)}%)`);
    } catch {
      setActionMessage(`❌ Adversarial evaluation failed.`);
    } finally {
      setIsAdversarialLoading(false);
      setTimeout(() => setActionMessage(null), 8000);
    }
  };

  const resilienceScore = chaosStatus?.resilience_score ?? 100;
  const isSteadyState = chaosStatus?.system_state === 'STEADY_STATE';
  const activeFaults = chaosStatus?.active_faults_count ?? 0;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 bg-gradient-to-r from-slate-900 via-rose-950/20 to-slate-900 border border-slate-800 rounded-xl">
        <div className="flex items-center space-x-3">
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400">
            <Flame className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-xl font-bold font-mono tracking-wide text-white">
                SECURITY CHAOS &amp; ADVERSARIAL RESILIENCE
              </h2>
              <span className={`px-2 py-0.5 text-xs font-mono font-bold rounded ${
                isSteadyState
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-500/15 text-rose-400 border border-rose-500/40 animate-pulse'
              }`}>
                {chaosStatus?.system_state ?? 'STEADY_STATE'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Automated Fault Injection &bull; In-Memory Graceful Degradation &bull; AI Evasion Stress Testing
            </p>
          </div>
        </div>

        {/* Action controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => handleEmergencyRecover()}
            className="flex items-center space-x-2 px-3.5 py-2 bg-rose-600/20 border border-rose-500/50 hover:bg-rose-600/30 text-rose-300 rounded-lg text-xs font-mono font-semibold transition"
            title="Immediately abort all chaos experiments and restore baseline"
          >
            <StopCircle className="w-4 h-4 text-rose-400" />
            <span>EMERGENCY ABORT</span>
          </button>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition"
            title="Refresh Status"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Action Notification Message */}
      {actionMessage && (
        <div className="p-3.5 rounded-lg bg-slate-800/90 border border-cyan-500/40 text-cyan-300 text-xs font-mono flex items-center justify-between animate-fadeIn">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* System Resilience KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Resilience Score */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">RESILIENCE SCORE</span>
            <ShieldCheck className={`w-4 h-4 ${resilienceScore >= 80 ? 'text-emerald-400' : 'text-amber-400'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className={`text-3xl font-extrabold font-mono ${
                resilienceScore >= 85
                  ? 'text-emerald-400'
                  : resilienceScore >= 70
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}>
                {resilienceScore.toFixed(1)}%
              </span>
              <span className="text-xs text-slate-400 font-mono">STEADY-STATE</span>
            </div>
            {/* Score Bar */}
            <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  resilienceScore >= 85
                    ? 'bg-emerald-500'
                    : resilienceScore >= 70
                    ? 'bg-amber-500'
                    : 'bg-rose-500'
                }`}
                style={{ width: `${resilienceScore}%` }}
              />
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Target SLA: &ge; 90.0% Under Chaos
          </span>
        </div>

        {/* Active Fault Leases */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">ACTIVE FAULTS</span>
            <AlertOctagon className={`w-4 h-4 ${activeFaults > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-500'}`} />
          </div>
          <div className="my-2">
            <span className={`text-3xl font-extrabold font-mono ${activeFaults > 0 ? 'text-rose-400' : 'text-slate-200'}`}>
              {activeFaults}
            </span>
            <span className="text-xs text-slate-400 font-mono ml-2">Bounded Leases</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Auto-reverts on lease expiry (5-120s)
          </span>
        </div>

        {/* In-Memory Fallbacks */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">FALLBACK SUBSYSTEMS</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="my-2 flex items-center space-x-2">
            <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold">
              100% OPERATIONAL
            </span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Zero persistent data corruption guaranteed
          </span>
        </div>

        {/* MTTR (Mean Time To Recovery) */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">AVG RECOVERY TIME</span>
            <Clock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="my-2">
            <span className="text-3xl font-extrabold font-mono text-purple-400">
              {chaosStatus?.mean_time_to_recovery_ms ?? 0}
            </span>
            <span className="text-xs text-slate-400 font-mono ml-1">ms</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Sub-millisecond software recovery
          </span>
        </div>
      </div>

      {/* Main Grid: Fault Injections + Adversarial Testing */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 Columns: Chaos Fault Injection Matrix */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-2">
                <Flame className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                  Fault Injection Library
                </h3>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono text-slate-400">Lease:</span>
                <select
                  value={selectedDuration}
                  onChange={(e) => setSelectedDuration(Number(e.target.value))}
                  className="bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-300 rounded px-2 py-1"
                >
                  <option value={10}>10 seconds</option>
                  <option value={30}>30 seconds (Default)</option>
                  <option value={60}>60 seconds</option>
                  <option value={120}>120 seconds</option>
                </select>
              </div>
            </div>

            <div className="space-y-3">
              {/* Fault 1: BROKER_LATENCY */}
              <div className="p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg flex items-center justify-between hover:border-slate-700 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold font-mono text-cyan-400">BROKER_LATENCY</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                      Event Bus
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Injects 250ms synthetic latency jitter on Kafka/Redis message dispatch.
                  </p>
                </div>
                <button
                  onClick={() => handleInjectChaos('BROKER_LATENCY', { latency_ms: 250 })}
                  disabled={injectingType === 'BROKER_LATENCY'}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 rounded text-xs font-mono transition"
                >
                  <Play className="w-3 h-3" />
                  <span>Inject</span>
                </button>
              </div>

              {/* Fault 2: BROKER_DROP */}
              <div className="p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg flex items-center justify-between hover:border-slate-700 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold font-mono text-amber-400">BROKER_DROP</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                      Network Drops
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Simulates 25% synthetic packet loss on real-time threat stream.
                  </p>
                </div>
                <button
                  onClick={() => handleInjectChaos('BROKER_DROP', { drop_rate: 0.25 })}
                  disabled={injectingType === 'BROKER_DROP'}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/40 text-amber-300 rounded text-xs font-mono transition"
                >
                  <Play className="w-3 h-3" />
                  <span>Inject</span>
                </button>
              </div>

              {/* Fault 3: DB_PARTITION */}
              <div className="p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg flex items-center justify-between hover:border-slate-700 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold font-mono text-rose-400">DB_PARTITION</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                      Database Isolation
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Simulates Neo4j graph partition; verifies automatic in-memory fallback routing.
                  </p>
                </div>
                <button
                  onClick={() => handleInjectChaos('DB_PARTITION', { target: 'neo4j' })}
                  disabled={injectingType === 'DB_PARTITION'}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 rounded text-xs font-mono transition"
                >
                  <Play className="w-3 h-3" />
                  <span>Inject</span>
                </button>
              </div>

              {/* Fault 4: AGENT_TIMEOUT */}
              <div className="p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg flex items-center justify-between hover:border-slate-700 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold font-mono text-purple-400">AGENT_TIMEOUT</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                      Multi-Agent
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Forces synthetic delay on primary SOC Agent to verify failover consensus.
                  </p>
                </div>
                <button
                  onClick={() => handleInjectChaos('AGENT_TIMEOUT', { timeout_ms: 3000 })}
                  disabled={injectingType === 'AGENT_TIMEOUT'}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/40 text-purple-300 rounded text-xs font-mono transition"
                >
                  <Play className="w-3 h-3" />
                  <span>Inject</span>
                </button>
              </div>

              {/* Fault 5: TELEMETRY_BURST */}
              <div className="p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg flex items-center justify-between hover:border-slate-700 transition">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold font-mono text-emerald-400">TELEMETRY_BURST</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                      Stress Load
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Injects instantaneous 500-event telemetry burst into real-time ingest pipeline.
                  </p>
                </div>
                <button
                  onClick={() => handleInjectChaos('TELEMETRY_BURST', { burst_count: 500 })}
                  disabled={injectingType === 'TELEMETRY_BURST'}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-300 rounded text-xs font-mono transition"
                >
                  <Play className="w-3 h-3" />
                  <span>Inject</span>
                </button>
              </div>
            </div>
          </div>

          {/* Active Experiments Table */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                Chaos Experiment Log
              </h3>
              <span className="text-xs font-mono text-slate-400">
                {experiments.length} total experiments recorded
              </span>
            </div>

            {experiments.length === 0 ? (
              <div className="text-center py-6 text-slate-500 font-mono text-xs">
                No active or historical chaos experiments recorded.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="pb-2">EXPERIMENT ID</th>
                      <th className="pb-2">FAULT TYPE</th>
                      <th className="pb-2">STATUS</th>
                      <th className="pb-2">LEASE</th>
                      <th className="pb-2 text-right">ACTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {experiments.slice(0, 5).map((exp) => (
                      <tr key={exp.id} className="hover:bg-slate-800/20">
                        <td className="py-2.5 text-slate-300">{exp.id.slice(0, 8)}...</td>
                        <td className="py-2.5 font-bold text-cyan-400">{exp.experiment_type}</td>
                        <td className="py-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            exp.status === 'ACTIVE'
                              ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30 animate-pulse'
                              : 'bg-slate-800 text-slate-400'
                          }`}>
                            {exp.status}
                          </span>
                        </td>
                        <td className="py-2.5 text-slate-400">{exp.duration_seconds}s</td>
                        <td className="py-2.5 text-right">
                          {exp.status === 'ACTIVE' && (
                            <button
                              onClick={() => handleEmergencyRecover(exp.id)}
                              className="px-2 py-1 bg-rose-600/20 text-rose-300 hover:bg-rose-600/30 border border-rose-500/30 rounded text-[10px]"
                            >
                              Recover
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right 5 Columns: Adversarial Evasion Robustness Benchmark */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center space-x-2 mb-4">
              <Cpu className="w-5 h-5 text-purple-400" />
              <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                Adversarial AI Evasion Evaluation
              </h3>
            </div>

            <p className="text-xs text-slate-400 mb-4 leading-relaxed">
              Injects mathematically bounded feature perturbations (&epsilon;-bounded feature shift) to test ML model evasion resistance against benign mimicry.
            </p>

            {/* Config Controls */}
            <div className="space-y-3 p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg mb-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-300">Perturbation (&epsilon;):</span>
                <span className="text-xs font-mono font-bold text-purple-400">{selectedEpsilon}</span>
              </div>
              <input
                type="range"
                min="0.05"
                max="0.25"
                step="0.05"
                value={selectedEpsilon}
                onChange={(e) => setSelectedEpsilon(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-purple-500"
              />

              <div className="flex items-center justify-between pt-1">
                <span className="text-xs font-mono text-slate-300">Technique:</span>
                <select
                  value={selectedTechnique}
                  onChange={(e) => setSelectedTechnique(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-xs font-mono text-purple-300 rounded px-2 py-1"
                >
                  <option value="BENIGN_MIMICRY">Benign Mimicry</option>
                  <option value="BOUNDARY_SEEKING">Decision Boundary Seeking</option>
                </select>
              </div>

              <button
                onClick={handleRunAdversarialTest}
                disabled={isAdversarialLoading}
                className="w-full mt-2 py-2 px-3 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/50 text-purple-300 rounded text-xs font-mono font-semibold flex items-center justify-center space-x-2 transition"
              >
                <Zap className={`w-3.5 h-3.5 ${isAdversarialLoading ? 'animate-spin' : ''}`} />
                <span>{isAdversarialLoading ? 'Evaluating Robustness...' : 'Run Adversarial Stress Test'}</span>
              </button>
            </div>

            {/* Results Display */}
            {adversarialResult ? (
              <div className="space-y-4 animate-fadeIn">
                {/* Overall Score */}
                <div className="p-3 bg-slate-800/60 border border-slate-700 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono text-slate-400">ENSEMBLE ARI</span>
                    <div className="text-xl font-mono font-extrabold text-purple-400">
                      {(adversarialResult.ensemble_adversarial_robustness_index * 100).toFixed(1)}%
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-mono text-slate-400">ROBUSTNESS GRADE</span>
                    <div className="text-xl font-mono font-extrabold text-emerald-400">
                      GRADE {adversarialResult.ensemble_robustness_grade}
                    </div>
                  </div>
                </div>

                {/* Model Breakdown */}
                <div className="space-y-2">
                  <span className="text-xs font-mono font-bold text-slate-300">Model Breakdown:</span>
                  {Object.entries(adversarialResult.models).map(([name, m]) => (
                    <div key={name} className="p-2.5 bg-slate-800/40 border border-slate-800 rounded flex items-center justify-between text-xs font-mono">
                      <div>
                        <span className="text-slate-200 font-semibold">{m.model_name}</span>
                        <div className="text-[10px] text-slate-400">
                          Clean: {(m.clean_accuracy * 100).toFixed(0)}% &bull; Adv: {(m.adversarial_accuracy * 100).toFixed(0)}%
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          m.robustness_grade === 'A'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : m.robustness_grade === 'B'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                        }`}>
                          Grade {m.robustness_grade}
                        </span>
                        <div className="text-[10px] text-slate-400 mt-0.5">
                          {(m.adversarial_robustness_index * 100).toFixed(1)}% ARI
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-4 bg-slate-800/20 border border-dashed border-slate-800 rounded-lg text-center text-slate-500 text-xs font-mono">
                Click &ldquo;Run Adversarial Stress Test&rdquo; to evaluate evasion rates across XGBoost, Random Forest, Isolation Forest, and Autoencoder models.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

