import React, { useState, useEffect } from 'react';
import {
  GitFork,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  Zap,
  Layers,
  ArrowRight,
  Database,
  Key,
  Server,
  Lock,
  Scissors,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Target,
  Activity,
  Cpu,
} from 'lucide-react';
import { api } from '../services/api';
import {
  CrownJewel,
  AttackPath,
  ChokePoint,
  ExposureMetrics,
} from '../types';

export const AttackPathView: React.FC = () => {
  const [metrics, setMetrics] = useState<ExposureMetrics | null>(null);
  const [crownJewels, setCrownJewels] = useState<CrownJewel[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [chokePoints, setChokePoints] = useState<ChokePoint[]>([]);
  const [activeTab, setActiveTab] = useState<'paths' | 'chokepoints' | 'crownjewels'>('paths');

  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [m, cj, ap, cp] = await Promise.all([
        api.getExposureMetrics(),
        api.getCrownJewels(),
        api.getAttackPaths(),
        api.getChokePoints(),
      ]);
      setMetrics(m);
      setCrownJewels(cj);
      setAttackPaths(ap);
      setChokePoints(cp);

      if (ap.length > 0 && !selectedPath) {
        setSelectedPath(ap[0]);
      }
    } catch (err) {
      console.error('Failed to load exposure data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRemediateChokePoint = async (chokePointId: string) => {
    try {
      setRemediatingId(chokePointId);
      const res = await api.remediateChokePoint(chokePointId);
      if (res) {
        await loadData();
      }
    } catch (err) {
      console.error('Choke point remediation failed:', err);
    } finally {
      setRemediatingId(null);
    }
  };

  const handleResetGraph = async () => {
    try {
      setLoading(true);
      await api.resetExposureGraph();
      await loadData();
    } catch (err) {
      console.error('Reset exposure graph failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const getNodeBadgeColor = (nodeType: string) => {
    switch (nodeType) {
      case 'PERIMETER_ENTRY':
        return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'INTERNAL_PIVOT':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'LATERAL_WORKSTATION':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'PRIVILEGE_ESCALATION':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'CROWN_JEWEL_TARGET':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/50 font-bold';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-slate-900/60 p-5 rounded-xl border border-slate-800 backdrop-blur">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-400">
              <GitFork className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-wider text-slate-100 uppercase font-mono">
                  Attack Paths & Choke Point Validation
                </h1>
                <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-orange-500/10 text-orange-400 border border-orange-500/30">
                  MINIMAL CUT SET
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Directed Multi-Hop Attack Traversal &bull; Graph Choke Point Optimization &bull; Crown Jewel Isolation
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleResetGraph}
            disabled={loading}
            className="flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition border border-slate-700"
            title="Reset exposure graph remediations to baseline"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Baseline</span>
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gradient-to-r from-orange-600 to-amber-600 hover:from-orange-500 hover:to-amber-500 text-white text-xs font-bold font-mono transition shadow-lg shadow-orange-950/40 border border-orange-500/40"
          >
            <Activity className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Evaluate Exposure</span>
          </button>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Path Resilience Index</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {metrics ? `${metrics.attack_path_resilience_index}` : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">
            {metrics && metrics.severed_attack_paths_count > 0
              ? `+${(metrics.attack_path_resilience_index - 78.5).toFixed(1)}% via choke point cuts`
              : 'Baseline graph resilience'}
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Attack Paths</span>
            <GitFork className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics ? metrics.active_attack_paths_count : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">active / {metrics?.total_attack_paths_discovered}</span>
          </div>
          <p className="text-[10px] text-emerald-400 font-mono mt-1">
            {metrics ? `${metrics.severed_attack_paths_count} severed paths` : '--'}
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Graph Choke Points</span>
            <Scissors className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">
              {metrics ? metrics.total_choke_points_identified : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">critical</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">
            {metrics ? `${metrics.remediated_choke_points_count} remediated` : '--'}
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Crown Jewels</span>
            <Lock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-purple-400">
              {metrics ? metrics.total_crown_jewels : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">monitored</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">
            {metrics ? `${metrics.isolated_crown_jewels_count} fully isolated` : '--'}
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Mean Path Length</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-amber-400">
              {metrics ? `${metrics.mean_attack_path_length_hops}` : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">hops to target</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Multi-stage traversal depth</p>
        </div>
      </div>

      {/* Subnavigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-4">
        <button
          onClick={() => setActiveTab('paths')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'paths'
              ? 'text-orange-400 border-b-2 border-orange-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitFork className="w-4 h-4" />
          <span>Attack Paths ({attackPaths.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('chokepoints')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'chokepoints'
              ? 'text-orange-400 border-b-2 border-orange-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Scissors className="w-4 h-4" />
          <span>Choke Point Optimizer ({chokePoints.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('crownjewels')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'crownjewels'
              ? 'text-orange-400 border-b-2 border-orange-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>Crown Jewels Matrix ({crownJewels.length})</span>
        </button>
      </div>

      {/* Tab 1: Attack Paths Explorer */}
      {activeTab === 'paths' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Paths List (Left 1 col) */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Discovered Multi-Hop Paths:
            </h3>
            {attackPaths.map((path) => (
              <div
                key={path.path_id}
                onClick={() => setSelectedPath(path)}
                className={`p-4 rounded-xl border transition cursor-pointer ${
                  selectedPath?.path_id === path.path_id
                    ? 'bg-slate-900/90 border-orange-500/60 shadow-lg shadow-orange-950/30'
                    : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-orange-400">{path.path_id}</span>
                  {path.status === 'SEVERED' ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1">
                      <ShieldCheck className="w-3 h-3 mr-1" />
                      SEVERED
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-red-500/10 text-red-400 border border-red-500/30 flex items-center space-x-1">
                      <AlertTriangle className="w-3 h-3 mr-1" />
                      ACTIVE THREAT
                    </span>
                  )}
                </div>

                <h4 className="text-xs font-bold text-slate-200 font-mono mt-1.5 line-clamp-2">
                  {path.title}
                </h4>

                <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                  <span>{path.hop_count} Hops</span>
                  <span className="text-amber-400 font-semibold">Risk: {path.accumulated_risk_score}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Path Node Breakdown (Right 2 cols) */}
          <div className="lg:col-span-2 space-y-4">
            {selectedPath ? (
              <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-orange-500/10 text-orange-400 border border-orange-500/30">
                        {selectedPath.path_id}
                      </span>
                      <h3 className="text-base font-bold text-slate-100 font-mono">
                        {selectedPath.title}
                      </h3>
                    </div>
                    <p className="text-xs text-slate-400 font-mono mt-1">
                      Target: <span className="text-purple-400 font-semibold">{selectedPath.target_crown_jewel_name}</span> &bull;{' '}
                      Entry: <span className="text-slate-300">{selectedPath.entry_point}</span>
                    </p>
                  </div>

                  <div className="text-right">
                    <span className="text-xs font-mono text-slate-400">Accumulated Path Risk</span>
                    <div className="text-xl font-bold font-mono text-red-400">
                      {selectedPath.accumulated_risk_score} / 100
                    </div>
                  </div>
                </div>

                {selectedPath.status === 'SEVERED' && (
                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                    <span>
                      Attack Path Severed by Choke Point{' '}
                      <span className="font-bold underline">{selectedPath.severed_by_choke_point}</span> at{' '}
                      {selectedPath.severed_at ? new Date(selectedPath.severed_at).toLocaleTimeString() : ''}. Target crown jewel is unreachable via this route.
                    </span>
                  </div>
                )}

                {/* Node-by-Node Breadcrumb */}
                <div className="space-y-4">
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                    Sequential Attack Progression ({selectedPath.nodes.length} Steps):
                  </h4>

                  {selectedPath.nodes.map((node, idx) => (
                    <div
                      key={node.step_order}
                      className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center space-x-3">
                          <span className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800 text-slate-300 text-xs font-mono font-bold">
                            {node.step_order}
                          </span>
                          <div>
                            <div className="flex items-center space-x-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-mono border ${getNodeBadgeColor(
                                  node.node_type
                                )}`}
                              >
                                {node.node_type}
                              </span>
                              <span className="text-sm font-semibold text-slate-200">
                                {node.asset_name}
                              </span>
                            </div>
                            <span className="text-xs text-slate-400 font-mono mt-0.5 block">
                              Asset ID: {node.asset_id}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center space-x-3 text-xs font-mono">
                          <span className="text-amber-400 font-semibold">
                            +{node.risk_contribution} Risk
                          </span>
                        </div>
                      </div>

                      <div className="mt-3 pt-3 border-t border-slate-900 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                        <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
                          <span className="text-slate-500 block mb-1">MITRE ATT&CK Technique:</span>
                          <span className="text-cyan-400">
                            [{node.technique_id}] {node.technique_name}
                          </span>
                        </div>
                        <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800">
                          <span className="text-slate-500 block mb-1">Exploited CVE / Vector:</span>
                          <span className={node.cve_id ? 'text-red-400 font-semibold' : 'text-slate-400'}>
                            {node.cve_id || 'Living-off-the-Land (LOLBAS) / Misconfiguration'}
                          </span>
                        </div>
                      </div>

                      <p className="mt-2 text-xs text-slate-400 bg-slate-900/40 p-2 rounded font-sans">
                        {node.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500 font-mono text-xs">
                Select an attack path to inspect multi-hop traversal details.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Choke Point Optimizer */}
      {activeTab === 'chokepoints' && (
        <div className="space-y-4">
          <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 text-xs font-mono flex items-center justify-between">
            <span className="text-slate-400">
              Graph Bottlenecks Identified: <span className="text-slate-200 font-bold">{chokePoints.length}</span>
            </span>
            <span className="text-slate-400">
              Remediating high-efficiency choke points severs multiple multi-hop attack paths simultaneously.
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {chokePoints.map((cp) => (
              <div
                key={cp.choke_point_id}
                className={`p-5 rounded-xl border transition ${
                  cp.is_remediated
                    ? 'bg-emerald-950/20 border-emerald-500/40'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        {cp.choke_point_id}
                      </span>
                      <span className="text-xs font-mono text-purple-400">{cp.category}</span>
                    </div>
                    <h3 className="text-base font-bold text-slate-100 font-mono mt-1.5">
                      {cp.title}
                    </h3>
                  </div>

                  <div className="text-right">
                    <span className="text-xs font-mono text-slate-400">Path Severance</span>
                    <div className="text-xl font-bold font-mono text-emerald-400">
                      {cp.disruption_efficiency_percent}%
                    </div>
                  </div>
                </div>

                <p className="text-xs text-slate-400 mt-2">{cp.description}</p>

                <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500">Affected Paths:</span>
                    <div className="flex space-x-1.5">
                      {cp.affected_path_ids.map((pid) => (
                        <span key={pid} className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                          {pid}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800 mt-2">
                    <span className="text-slate-500 block mb-1">Recommended Policy Cut:</span>
                    <span className="text-amber-400 font-semibold">{cp.remediation_action}</span>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  {cp.is_remediated ? (
                    <span className="text-xs font-mono text-emerald-400 flex items-center space-x-1">
                      <CheckCircle2 className="w-4 h-4 mr-1" />
                      Remediated & Paths Severed
                    </span>
                  ) : (
                    <span className="text-xs font-mono text-slate-400">
                      Disrupts {cp.affected_paths_count} active paths
                    </span>
                  )}

                  <button
                    onClick={() => handleRemediateChokePoint(cp.choke_point_id)}
                    disabled={cp.is_remediated || remediatingId === cp.choke_point_id}
                    className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition ${
                      cp.is_remediated
                        ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                        : 'bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-400'
                    }`}
                  >
                    <Scissors className={`w-3.5 h-3.5 ${remediatingId === cp.choke_point_id ? 'animate-spin' : ''}`} />
                    <span>{cp.is_remediated ? 'Policy Cut Applied' : 'Simulate Policy Cut'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Crown Jewels Matrix */}
      {activeTab === 'crownjewels' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {crownJewels.map((cj) => (
            <div
              key={cj.id}
              className={`p-5 rounded-xl border transition ${
                cj.is_isolated
                  ? 'bg-emerald-950/20 border-emerald-500/40 shadow-lg shadow-emerald-950/30'
                  : 'bg-slate-900/60 border-slate-800'
              }`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
                      {cj.id}
                    </span>
                    <span className="text-xs font-mono text-amber-400">{cj.asset_tier}</span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100 font-mono mt-1.5">
                    {cj.name}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    {cj.hostname} &bull; {cj.ip_address}
                  </p>
                </div>

                <div className="text-right">
                  <span className="text-xs font-mono text-slate-400">Inbound Paths</span>
                  <div className={`text-xl font-bold font-mono ${cj.inbound_paths_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {cj.inbound_paths_count} Active
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-3 text-xs font-mono">
                <div>
                  <span className="text-slate-500">Category:</span>
                  <p className="text-slate-300">{cj.category}</p>
                </div>
                <div>
                  <span className="text-slate-500">Data Classification:</span>
                  <p className="text-slate-300">{cj.data_classification}</p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80">
                <span className="text-xs font-mono text-slate-400 block mb-1.5">
                  Active Compensating Controls:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {cj.compensating_controls.map((ctrl, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1"
                    >
                      <ShieldCheck className="w-3 h-3 text-emerald-400 mr-1" />
                      {ctrl}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

