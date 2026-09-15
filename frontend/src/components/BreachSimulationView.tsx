import React, { useState, useEffect } from 'react';
import {
  Crosshair,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  Clock,
  Layers,
  CheckCircle2,
  XCircle,
  Eye,
  Activity,
  Zap,
  Terminal,
  Server,
  FileText,
  Lock,
  ChevronRight,
  Sparkles,
} from 'lucide-react';
import { api } from '../services/api';
import {
  AptCampaignProfile,
  SimulationResult,
  CoverageMatrixItem,
  BasMetrics,
} from '../types';

export const BreachSimulationView: React.FC = () => {
  const [metrics, setMetrics] = useState<BasMetrics | null>(null);
  const [campaigns, setCampaigns] = useState<AptCampaignProfile[]>([]);
  const [simulations, setSimulations] = useState<SimulationResult[]>([]);
  const [coverageMatrix, setCoverageMatrix] = useState<CoverageMatrixItem[]>([]);
  const [activeTab, setActiveTab] = useState<'campaigns' | 'runner' | 'matrix' | 'history'>('campaigns');

  const [selectedCampaign, setSelectedCampaign] = useState<AptCampaignProfile | null>(null);
  const [currentSimulation, setCurrentSimulation] = useState<SimulationResult | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [targetEnv, setTargetEnv] = useState('Simulated Multi-VPC Cloud & On-Premises Range');
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [m, c, s, cm] = await Promise.all([
        api.getBasMetrics(),
        api.getBasCampaigns(),
        api.getBasSimulations(20),
        api.getBasCoverageMatrix(),
      ]);
      setMetrics(m);
      setCampaigns(c);
      setSimulations(s);
      setCoverageMatrix(cm);

      if (c.length > 0 && !selectedCampaign) {
        setSelectedCampaign(c[0]);
      }
      if (s.length > 0 && !currentSimulation) {
        setCurrentSimulation(s[0]);
      }
    } catch (err) {
      console.error('Failed to load BAS data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleLaunchCampaign = async (campaignId: string) => {
    try {
      setIsSimulating(true);
      setActiveTab('runner');
      const res = await api.executeBasCampaign(campaignId, targetEnv, false);
      if (res) {
        setCurrentSimulation(res);
        await loadData();
      }
    } catch (err) {
      console.error('Simulation execution failed:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PREVENTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3.5 h-3.5 mr-1" />
            PREVENTED
          </span>
        );
      case 'DETECTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Eye className="w-3.5 h-3.5 mr-1" />
            DETECTED
          </span>
        );
      case 'EVADED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3.5 h-3.5 mr-1" />
            EVADED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            {status}
          </span>
        );
    }
  };

  const tacticsList = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-slate-900/60 p-5 rounded-xl border border-slate-800 backdrop-blur">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
              <Crosshair className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-wider text-slate-100 uppercase font-mono">
                  Autonomous Breach & Attack Simulation (BAS)
                </h1>
                <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-red-500/10 text-red-400 border border-red-500/30">
                  APT EMULATION
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Continuous Multi-Stage Adversary Emulation &bull; Safe Software Probing &bull; MITRE ATT&CK Coverage
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition border border-slate-700"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => handleLaunchCampaign(selectedCampaign?.campaign_id || 'APT29')}
            disabled={isSimulating}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white text-xs font-bold font-mono transition shadow-lg shadow-red-950/40 border border-red-500/40 disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'SIMULATING KILL CHAIN...' : `EMULATE ${selectedCampaign?.campaign_id || 'APT29'}`}</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">BAS Posture Score</span>
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">
              {metrics ? `${metrics.overall_posture_score}` : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <p className="text-[10px] text-emerald-400 font-mono mt-1 flex items-center">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span>
            STRONG DEFENSE RESILIENCE
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Prevention Rate</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {metrics ? `${metrics.prevention_rate_percent}%` : '--'}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Autonomous inline blocks</p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Detection Rate</span>
            <Eye className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-amber-400">
              {metrics ? `${metrics.detection_rate_percent}%` : '--'}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Telemetry & Sigma matches</p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Mean Time to Block</span>
            <Zap className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-indigo-400">
              {metrics ? `${metrics.mean_time_to_block_ms}ms` : '--'}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Zero-downtime policy latency</p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">ATT&CK Techniques</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-purple-400">
              {metrics ? metrics.mitre_techniques_covered : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">covered</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">0 unmitigated blindspots</p>
        </div>
      </div>

      {/* Subnavigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-4">
        <button
          onClick={() => setActiveTab('campaigns')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'campaigns'
              ? 'text-red-400 border-b-2 border-red-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Crosshair className="w-4 h-4" />
          <span>Adversary Campaigns ({campaigns.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('runner')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'runner'
              ? 'text-red-400 border-b-2 border-red-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Kill Chain Runner</span>
          {isSimulating && <span className="w-2 h-2 rounded-full bg-red-400 animate-ping"></span>}
        </button>
        <button
          onClick={() => setActiveTab('matrix')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'matrix'
              ? 'text-red-400 border-b-2 border-red-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>ATT&CK Defense Heatmap</span>
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'history'
              ? 'text-red-400 border-b-2 border-red-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Clock className="w-4 h-4" />
          <span>Simulation History ({simulations.length})</span>
        </button>
      </div>

      {/* Tab 1: Adversary Campaign Catalog */}
      {activeTab === 'campaigns' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {campaigns.map((camp) => (
            <div
              key={camp.campaign_id}
              className={`p-5 rounded-xl border transition cursor-pointer ${
                selectedCampaign?.campaign_id === camp.campaign_id
                  ? 'bg-slate-900/90 border-red-500/60 shadow-lg shadow-red-950/30'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
              onClick={() => setSelectedCampaign(camp)}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-red-500/10 text-red-400 border border-red-500/30">
                      {camp.campaign_id}
                    </span>
                    <span className="text-xs font-mono text-slate-400">{camp.actor_origin}</span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100 font-mono mt-1.5">
                    {camp.name}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">{camp.description}</p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-3 text-xs font-mono">
                <div>
                  <span className="text-slate-500">Actor Alias:</span>
                  <p className="text-slate-300 truncate">{camp.actor_alias}</p>
                </div>
                <div>
                  <span className="text-slate-500">Complexity:</span>
                  <p className="text-amber-400">{camp.complexity}</p>
                </div>
              </div>

              <div className="mt-3">
                <span className="text-[11px] text-slate-500 font-mono">Target Sectors:</span>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {camp.target_sectors.map((sec, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
                    >
                      {sec}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">
                  {camp.stages.length} Sequential Kill Chain Stages
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedCampaign(camp);
                    handleLaunchCampaign(camp.campaign_id);
                  }}
                  disabled={isSimulating}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 text-red-400 text-xs font-mono font-semibold transition"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Emulate Now</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Kill Chain Runner */}
      {activeTab === 'runner' && currentSimulation && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-red-500/10 text-red-400 border border-red-500/30">
                    {currentSimulation.campaign_id}
                  </span>
                  <h2 className="text-lg font-bold text-slate-100 font-mono">
                    {currentSimulation.campaign_name}
                  </h2>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Target Range: <span className="text-slate-300">{currentSimulation.target_environment}</span> &bull;
                  Executed: <span className="text-slate-300">{new Date(currentSimulation.started_at).toLocaleString()}</span>
                </p>
              </div>

              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <span className="text-xs font-mono text-slate-400">Campaign Posture</span>
                  <div className="text-xl font-bold font-mono text-emerald-400">
                    {currentSimulation.posture_score} / 100
                  </div>
                </div>
                <div className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs font-mono text-slate-300">
                  Verdict: <span className="font-bold text-emerald-400">{currentSimulation.summary_verdict}</span>
                </div>
              </div>
            </div>

            {/* Stages Timeline */}
            <div className="mt-5 space-y-3">
              <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                Multi-Stage Attack Path & Defensive Interceptions:
              </h3>
              {currentSimulation.stage_results.map((stage, idx) => (
                <div
                  key={stage.stage_id}
                  className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center space-x-3">
                      <span className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800 text-slate-300 text-xs font-mono font-bold">
                        {idx + 1}
                      </span>
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono text-purple-400">{stage.tactic}</span>
                          <span className="text-slate-600">&bull;</span>
                          <span className="text-xs font-mono text-slate-400">[{stage.technique_id}]</span>
                          <span className="text-sm font-semibold text-slate-200">{stage.stage_name}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Technique: <span className="text-slate-300">{stage.technique_name}</span>
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3">
                      <span className="text-xs font-mono text-slate-400">
                        {stage.execution_time_ms}ms
                      </span>
                      {getStatusBadge(stage.status)}
                    </div>
                  </div>

                  <div className="mt-3 pt-3 border-t border-slate-900 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-500 block mb-1">Detecting Defense Layer:</span>
                      <span className="text-cyan-400 font-semibold">{stage.detecting_layer}</span>
                    </div>
                    <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
                      <span className="text-slate-500 block mb-1">Recommended Mitigation:</span>
                      <span className="text-emerald-400">{stage.mitigation}</span>
                    </div>
                  </div>

                  {stage.payload_sample && (
                    <div className="mt-2 text-[11px] font-mono text-slate-500 bg-slate-900/40 px-2 py-1 rounded">
                      <span className="text-slate-400">Payload: </span>
                      {stage.payload_sample}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: ATT&CK Defense Heatmap Matrix */}
      {activeTab === 'matrix' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between bg-slate-900/60 p-4 rounded-xl border border-slate-800 text-xs font-mono">
            <span className="text-slate-400">
              Total Validated Techniques: <span className="text-slate-200 font-bold">{coverageMatrix.length}</span>
            </span>
            <div className="flex items-center space-x-4">
              <span className="flex items-center space-x-1.5 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                <span>Prevented ({coverageMatrix.filter((c) => c.status === 'PREVENTED').length})</span>
              </span>
              <span className="flex items-center space-x-1.5 text-amber-400">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                <span>Detected ({coverageMatrix.filter((c) => c.status === 'DETECTED').length})</span>
              </span>
              <span className="flex items-center space-x-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400"></span>
                <span>Evaded ({coverageMatrix.filter((c) => c.status === 'EVADED').length})</span>
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {tacticsList.map((tactic) => {
              const items = coverageMatrix.filter((c) => c.tactic.toLowerCase() === tactic.toLowerCase());
              if (items.length === 0) return null;
              return (
                <div key={tactic} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur">
                  <h4 className="text-xs font-bold font-mono text-purple-400 uppercase tracking-wider pb-2 border-b border-slate-800 flex items-center justify-between">
                    <span>{tactic}</span>
                    <span className="text-slate-500 font-normal">({items.length})</span>
                  </h4>
                  <div className="mt-3 space-y-2">
                    {items.map((item) => (
                      <div
                        key={item.technique_id}
                        className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-cyan-400 text-[11px] font-semibold">
                            {item.technique_id}
                          </span>
                          {getStatusBadge(item.status)}
                        </div>
                        <p className="font-medium text-slate-200 mt-1">{item.technique_name}</p>
                        <p className="text-[11px] text-slate-400 font-mono mt-1 truncate">
                          Layer: {item.detecting_layer}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 4: Simulation Run History */}
      {activeTab === 'history' && (
        <div className="space-y-3">
          {simulations.map((sim) => (
            <div
              key={sim.simulation_id}
              className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div>
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-red-500/10 text-red-400 border border-red-500/30">
                    {sim.campaign_id}
                  </span>
                  <h4 className="text-sm font-bold text-slate-200 font-mono">{sim.campaign_name}</h4>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  ID: <span className="text-slate-500">{sim.simulation_id}</span> &bull; Target: {sim.target_environment} &bull; Executed:{' '}
                  {new Date(sim.started_at).toLocaleString()}
                </p>
              </div>

              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <span className="text-xs font-mono text-slate-400">Posture Score</span>
                  <div className="text-base font-bold font-mono text-emerald-400">
                    {sim.posture_score}%
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono text-slate-400">Blocked</span>
                  <div className="text-base font-bold font-mono text-cyan-400">
                    {sim.prevented_stages} / {sim.total_stages}
                  </div>
                </div>
                <button
                  onClick={() => {
                    setCurrentSimulation(sim);
                    setActiveTab('runner');
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition"
                >
                  View Run
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

