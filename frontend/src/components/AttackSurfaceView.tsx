import React, { useState, useEffect } from 'react';
import {
  Target,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Server,
  CheckCircle2,
  Clock,
  Flame,
  Zap,
  RefreshCw,
  Search,
  Filter,
  Lock,
  Layers,
  Activity,
  Play,
  X,
  ExternalLink,
} from 'lucide-react';
import { api } from '../services/api';
import {
  AsmMetrics,
  DiscoveredAsset,
  PrioritizedVulnerability,
  AssetCriticalityTier,
  ExposureLevel,
  VulnerabilityPriority,
  VulnerabilityStatus,
} from '../types';

export const AttackSurfaceView: React.FC = () => {
  const [metrics, setMetrics] = useState<AsmMetrics | null>(null);
  const [assets, setAssets] = useState<DiscoveredAsset[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<PrioritizedVulnerability[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'assets' | 'scanner'>('vulnerabilities');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Vulnerability filters
  const [vulnPriorityFilter, setVulnPriorityFilter] = useState<string>('ALL');
  const [vulnStatusFilter, setVulnStatusFilter] = useState<string>('ACTIVE');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Asset filters
  const [assetExposureFilter, setAssetExposureFilter] = useState<string>('ALL');

  // Scanner state
  const [scanSubnet, setScanSubnet] = useState<string>('198.51.100.0/24');
  const [scanIntensity, setScanIntensity] = useState<string>('COMPREHENSIVE');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanLogs, setScanLogs] = useState<string[]>([]);

  // Remediation modal state
  const [selectedVuln, setSelectedVuln] = useState<PrioritizedVulnerability | null>(null);
  const [remediationAction, setRemediationAction] = useState<string>('APPLY_VIRTUAL_PATCH');
  const [remediationNotes, setRemediationNotes] = useState<string>('SOAR automated virtual patch deployed to perimeter gateway');
  const [isRemediating, setIsRemediating] = useState<boolean>(false);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [m, a, v] = await Promise.all([
        api.getAsmMetrics(),
        api.getAsmAssets(),
        api.getPrioritizedVulnerabilities(),
      ]);
      if (m) setMetrics(m);
      setAssets(a);
      setVulnerabilities(v);
    } catch {
      setActionMessage('Failed to connect to Attack Surface Management API');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRecalculatePriorities = async () => {
    setIsLoading(true);
    try {
      const updated = await api.recalculateVulnerabilityPriorities(true);
      setVulnerabilities(updated);
      const m = await api.getAsmMetrics();
      if (m) setMetrics(m);
      setActionMessage('Risk prioritization recalculated using latest EPSS and asset criticality weights');
      setTimeout(() => setActionMessage(null), 4000);
    } catch {
      setActionMessage('Failed to recalculate vulnerability priorities');
    } finally {
      setIsLoading(false);
    }
  };

  const handleTriggerScan = async () => {
    setIsScanning(true);
    setScanLogs((prev) => [
      `[${new Date().toLocaleTimeString()}] Initiating ${scanIntensity} scan across subnet ${scanSubnet}...`,
      ...prev,
    ]);
    try {
      const scanRes = await api.triggerAsmScan(scanSubnet, scanIntensity);
      if (scanRes) {
        setScanLogs((prev) => [
          `[${new Date().toLocaleTimeString()}] Scan complete! Discovered ${scanRes.assets_discovered} new asset(s). Total inventory: ${scanRes.total_assets}.`,
          ...prev,
        ]);
        setActionMessage(`Discovery scan completed. Total assets: ${scanRes.total_assets}`);
        setTimeout(() => setActionMessage(null), 4000);
      }
      await loadData();
    } catch {
      setScanLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] Error: Threat surface scan timed out or failed.`,
        ...prev,
      ]);
    } finally {
      setIsScanning(false);
    }
  };

  const handleRemediateSubmit = async () => {
    if (!selectedVuln) return;
    setIsRemediating(true);
    try {
      const res = await api.remediateVulnerability(
        selectedVuln.cve_id,
        remediationNotes,
        remediationAction
      );
      if (res) {
        setActionMessage(`Vulnerability ${selectedVuln.cve_id} successfully marked as REMEDIATED`);
        setTimeout(() => setActionMessage(null), 4000);
        setSelectedVuln(null);
        await loadData();
      }
    } catch {
      setActionMessage('Failed to remediate vulnerability');
    } finally {
      setIsRemediating(false);
    }
  };

  // Filtered vulnerabilities
  const filteredVulns = vulnerabilities.filter((v) => {
    if (vulnStatusFilter !== 'ALL' && v.status !== vulnStatusFilter) return false;
    if (vulnPriorityFilter !== 'ALL' && v.priority !== vulnPriorityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        v.cve_id.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.asset_hostname.toLowerCase().includes(q) ||
        v.affected_service.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Filtered assets
  const filteredAssets = assets.filter((a) => {
    if (assetExposureFilter !== 'ALL' && a.exposure !== assetExposureFilter) return false;
    return true;
  });

  const getPriorityColor = (priority: VulnerabilityPriority) => {
    switch (priority) {
      case 'P0_CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'P1_HIGH':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'P2_MEDIUM':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
      case 'P3_LOW':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    }
  };

  const getExposureBadge = (exposure: ExposureLevel) => {
    switch (exposure) {
      case 'INTERNET_FACING':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-red-900/40 text-red-300 border border-red-700/50">Internet-Facing</span>;
      case 'DMZ':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-amber-900/40 text-amber-300 border border-amber-700/50">DMZ Perimeter</span>;
      case 'INTERNAL_SEGMENTED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">Internal Segmented</span>;
      case 'AIR_GAPPED':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-blue-900/40 text-blue-300 border border-blue-700/50">Air-Gapped</span>;
    }
  };

  const getCriticalityBadge = (crit: AssetCriticalityTier) => {
    switch (crit) {
      case 'TIER_1_MISSION_CRITICAL':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-900/40 text-purple-300 border border-purple-700/50">Tier 1 Mission Critical</span>;
      case 'TIER_2_CORE_OPERATIONAL':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-900/40 text-cyan-300 border border-cyan-700/50">Tier 2 Operational</span>;
      case 'TIER_3_INTERNAL_SUPPORT':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300 border border-slate-700">Tier 3 Support</span>;
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 p-6 rounded-2xl backdrop-blur shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 text-indigo-400">
              <Target className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                Attack Surface Management (ASM) & RBVM
                <span className="px-2.5 py-0.5 text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 rounded-full">
                  Phase 18
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Continuous surface discovery, EPSS exploitability prioritization, and dynamic remediation SLAs
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRecalculatePriorities}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-sm font-medium transition shadow-sm hover:shadow"
          >
            <Zap className={`w-4 h-4 text-amber-400 ${isLoading ? 'animate-spin' : ''}`} />
            Recalculate Priorities
          </button>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-medium transition shadow-sm hover:shadow"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="flex items-center justify-between bg-indigo-950/80 border border-indigo-500/50 text-indigo-200 px-4 py-3 rounded-xl text-sm animate-fade-in shadow-lg">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-indigo-400" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Exposure Score */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Attack Surface Exposure</span>
            <Globe className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.attack_surface_exposure_score : '--'}
            </span>
            <span className="text-xs text-slate-400">/ 100 Index</span>
          </div>
          <div className="mt-3 w-full bg-slate-800 rounded-full h-2 overflow-hidden">
            <div
              className={`h-full rounded-full ${
                (metrics?.attack_surface_exposure_score || 0) > 70
                  ? 'bg-red-500'
                  : (metrics?.attack_surface_exposure_score || 0) > 40
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, metrics?.attack_surface_exposure_score || 0)}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>External Exposure Risk</span>
            <span className="text-amber-400 font-medium">Elevated DMZ</span>
          </p>
        </div>

        {/* Discovered Assets */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Discovered Assets</span>
            <Server className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.total_assets : '--'}
            </span>
            <span className="text-xs text-cyan-400">
              {metrics ? `${metrics.internet_facing_assets} Internet-Facing` : ''}
            </span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Internal Segmented</span>
            <span className="text-slate-300 font-medium">{metrics?.internal_assets || 0} hosts</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Cloud & On-Prem Coverage</span>
            <span className="text-emerald-400 font-medium">100% Mapped</span>
          </p>
        </div>

        {/* Exploit Prediction (EPSS) */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Mean EPSS Exploitability</span>
            <Flame className="w-5 h-5 text-red-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? `${(metrics.avg_epss_probability * 100).toFixed(1)}%` : '--'}
            </span>
            <span className="text-xs text-red-400 font-semibold">30-Day Weaponization</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Active Flaws Cataloged</span>
            <span className="text-slate-300 font-medium">{metrics?.active_vulnerabilities || 0} CVEs</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Known Exploits in Wild</span>
            <span className="text-red-400 font-semibold">5 Weaponized</span>
          </p>
        </div>

        {/* SLA Compliance */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Remediation SLA Rate</span>
            <Clock className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? `${metrics.sla_compliance_rate}%` : '--'}
            </span>
            <span className="text-xs text-emerald-400 font-semibold">On-Time Fixes</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>P0 Emergency (24h)</span>
            <span className="text-red-400 font-bold">{metrics?.p0_critical_count || 0} pending</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>P1 High (7d)</span>
            <span className="text-amber-400 font-medium">{metrics?.p1_high_count || 0} pending</span>
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setActiveTab('vulnerabilities')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'vulnerabilities'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-4 h-4" />
          Prioritized Vulnerabilities (RBVM)
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {vulnerabilities.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('assets')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'assets'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Server className="w-4 h-4" />
          Attack Surface Assets
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {assets.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('scanner')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'scanner'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          Continuous Surface Scanner
        </button>
      </div>

      {/* TAB 1: PRIORITIZED VULNERABILITIES */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 p-4 rounded-xl backdrop-blur">
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search CVE ID, service, title, or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center gap-3 w-full sm:w-auto">
              <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-1">
                {['ALL', 'P0_CRITICAL', 'P1_HIGH', 'P2_MEDIUM'].map((tier) => (
                  <button
                    key={tier}
                    onClick={() => setVulnPriorityFilter(tier)}
                    className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                      vulnPriorityFilter === tier
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tier.replace('_', ' ')}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-1">
                {['ACTIVE', 'REMEDIATED', 'ALL'].map((st) => (
                  <button
                    key={st}
                    onClick={() => setVulnStatusFilter(st)}
                    className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                      vulnStatusFilter === st
                        ? 'bg-slate-800 text-slate-200'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Vulnerabilities Table */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-xs font-semibold uppercase tracking-wider text-slate-400">
                    <th className="p-4">Contextual Risk Score</th>
                    <th className="p-4">Vulnerability / CVE</th>
                    <th className="p-4">Affected Asset & Service</th>
                    <th className="p-4">CVSS vs. EPSS</th>
                    <th className="p-4">Threat Intel Signals</th>
                    <th className="p-4">Remediation SLA</th>
                    <th className="p-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-sm">
                  {filteredVulns.map((v) => (
                    <tr key={v.cve_id} className="hover:bg-slate-800/40 transition">
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div
                            className={`w-12 h-12 rounded-xl flex items-center justify-center font-black text-lg border ${
                              v.contextual_risk_score >= 85
                                ? 'bg-red-500/20 text-red-400 border-red-500/50'
                                : v.contextual_risk_score >= 65
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/50'
                                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
                            }`}
                          >
                            {Math.round(v.contextual_risk_score)}
                          </div>
                          <div>
                            <span className={`px-2 py-0.5 text-xs font-semibold rounded border ${getPriorityColor(v.priority)}`}>
                              {v.priority.replace('_', ' ')}
                            </span>
                            <p className="text-xs text-slate-400 mt-1">
                              {v.status === 'REMEDIATED' ? (
                                <span className="text-emerald-400 font-medium flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" /> Remediated
                                </span>
                              ) : (
                                <span className="text-slate-400">Active Vulnerability</span>
                              )}
                            </p>
                          </div>
                        </div>
                      </td>

                      <td className="p-4">
                        <div className="font-semibold text-white">{v.cve_id}</div>
                        <div className="text-xs text-slate-400 max-w-xs truncate" title={v.title}>
                          {v.title}
                        </div>
                      </td>

                      <td className="p-4">
                        <div className="text-slate-200 font-medium">{v.asset_hostname}</div>
                        <div className="text-xs text-cyan-400 font-mono">{v.affected_service}</div>
                      </td>

                      <td className="p-4">
                        <div className="space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-slate-400">CVSS:</span>
                            <span className="font-bold text-slate-200">{v.cvss_score.toFixed(1)}</span>
                          </div>
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-slate-400">EPSS:</span>
                            <span className="font-bold text-red-400">{(v.epss_probability * 100).toFixed(1)}%</span>
                          </div>
                        </div>
                      </td>

                      <td className="p-4">
                        <div className="flex flex-wrap gap-1.5">
                          {v.has_known_exploit && (
                            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-950/60 text-red-300 border border-red-700/50 flex items-center gap-1">
                              <Flame className="w-3 h-3 text-red-400" /> Weaponized
                            </span>
                          )}
                          {v.cisa_kev && (
                            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-950/60 text-purple-300 border border-purple-700/50">
                              CISA KEV
                            </span>
                          )}
                          {v.score_breakdown?.zero_trust_discount ? (
                            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-950/60 text-emerald-300 border border-emerald-700/50 flex items-center gap-1">
                              <ShieldCheck className="w-3 h-3 text-emerald-400" /> ZT Compensating (-15)
                            </span>
                          ) : null}
                        </div>
                      </td>

                      <td className="p-4">
                        <div className="flex items-center gap-2 text-xs">
                          <Clock className="w-3.5 h-3.5 text-amber-400" />
                          <span className="font-medium text-slate-200">SLA: {v.sla_hours}h</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">{v.sla_description}</p>
                      </td>

                      <td className="p-4 text-right">
                        {v.status === 'ACTIVE' ? (
                          <button
                            onClick={() => {
                              setSelectedVuln(v);
                              setRemediationNotes(`Deploy automated SOAR virtual patch PB-402 against ${v.cve_id}`);
                            }}
                            className="px-3 py-1.5 bg-indigo-600/90 hover:bg-indigo-600 text-white rounded-lg text-xs font-semibold transition shadow-sm hover:shadow flex items-center gap-1.5 ml-auto"
                          >
                            <Shield className="w-3.5 h-3.5" />
                            Remediate
                          </button>
                        ) : (
                          <span className="text-xs text-emerald-400 font-medium">Closed</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {filteredVulns.length === 0 && (
                    <tr>
                      <td colSpan={7} className="p-8 text-center text-slate-500">
                        No vulnerabilities match the current filter criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DISCOVERED ASSETS */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 p-4 rounded-xl backdrop-blur">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <Filter className="w-4 h-4 text-indigo-400" />
              <span>Filter by Exposure:</span>
              <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-1 ml-2">
                {['ALL', 'INTERNET_FACING', 'DMZ', 'INTERNAL_SEGMENTED'].map((exp) => (
                  <button
                    key={exp}
                    onClick={() => setAssetExposureFilter(exp)}
                    className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                      assetExposureFilter === exp
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {exp.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <div className="text-xs text-slate-400">
              Showing <span className="text-white font-bold">{filteredAssets.length}</span> assets
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredAssets.map((asset) => (
              <div
                key={asset.id}
                className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div>
                      <h3 className="font-bold text-white text-base tracking-tight truncate max-w-[220px]" title={asset.hostname}>
                        {asset.hostname}
                      </h3>
                      <p className="text-xs font-mono text-indigo-400">{asset.ip_address}</p>
                    </div>
                    {getExposureBadge(asset.exposure)}
                  </div>

                  <div className="space-y-2 mb-4">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">Criticality:</span>
                      {getCriticalityBadge(asset.criticality)}
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">Environment:</span>
                      <span className="text-slate-200 font-medium">{asset.environment}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">Owner:</span>
                      <span className="text-slate-200 font-medium">{asset.owner_team}</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">Compensating ZTNA:</span>
                      {asset.has_zero_trust_control ? (
                        <span className="text-emerald-400 font-semibold flex items-center gap-1">
                          <ShieldCheck className="w-3.5 h-3.5" /> Enforced
                        </span>
                      ) : (
                        <span className="text-amber-400 font-semibold flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" /> None
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Open Ports & Services */}
                  <div className="space-y-1.5 pt-3 border-t border-slate-800">
                    <span className="text-xs font-semibold text-slate-400">Open Ports & Services:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {asset.open_ports.map((port) => (
                        <span key={port} className="px-2 py-0.5 text-xs font-mono bg-slate-950 text-cyan-300 border border-slate-800 rounded">
                          Port {port}
                        </span>
                      ))}
                      {asset.services.map((svc) => (
                        <span key={svc} className="px-2 py-0.5 text-xs bg-indigo-950/40 text-indigo-300 border border-indigo-800/40 rounded">
                          {svc}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                  <span className="text-slate-400">Active Vulnerabilities:</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded-full ${
                      asset.active_vulnerabilities_count > 0
                        ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    }`}
                  >
                    {asset.active_vulnerabilities_count} CVEs
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: CONTINUOUS SURFACE SCANNER */}
      {activeTab === 'scanner' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur space-y-5">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-indigo-400" />
              Threat Surface Scanner
            </h2>
            <p className="text-xs text-slate-400">
              Probes corporate CIDRs and public DMZ ranges to discover shadow IT, rogue endpoints, and open ports.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Target Subnet / CIDR</label>
                <input
                  type="text"
                  value={scanSubnet}
                  onChange={(e) => setScanSubnet(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 font-mono"
                  placeholder="e.g. 198.51.100.0/24"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">Scan Intensity</label>
                <select
                  value={scanIntensity}
                  onChange={(e) => setScanIntensity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="PASSIVE">PASSIVE (DNS & Certificate Transparency)</option>
                  <option value="STANDARD">STANDARD (Top 1000 Ports + HTTP Probes)</option>
                  <option value="COMPREHENSIVE">COMPREHENSIVE (Full 65k Ports + OS Fingerprinting)</option>
                </select>
              </div>

              <button
                onClick={handleTriggerScan}
                disabled={isScanning}
                className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition shadow-lg flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Scanning Subnet Surface...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    Launch Discovery Scan
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="lg:col-span-2 bg-slate-950 border border-slate-800 rounded-2xl p-6 flex flex-col font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <span className="text-slate-400 font-semibold flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Live ASM Discovery Scanner Log Stream
              </span>
              <span className="text-xs text-emerald-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Active Probing Daemon
              </span>
            </div>

            <div className="flex-1 overflow-y-auto max-h-[360px] space-y-2 text-slate-300">
              {scanLogs.length === 0 ? (
                <div className="text-slate-600 italic py-12 text-center">
                  Scanner idle. Configure subnet and trigger scan to inspect live surface discovery logs.
                </div>
              ) : (
                scanLogs.map((log, idx) => (
                  <div key={idx} className="leading-relaxed text-slate-300">
                    {log}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* REMEDIATION MODAL */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5 animate-scale-up">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-indigo-400" />
                  Remediate Vulnerability
                </h3>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  {selectedVuln.cve_id} &bull; {selectedVuln.asset_hostname}
                </p>
              </div>
              <button
                onClick={() => setSelectedVuln(null)}
                className="text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Contextual Risk Score:</span>
                <span className="font-bold text-red-400">{selectedVuln.contextual_risk_score} / 100</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Remediation SLA:</span>
                <span className="font-semibold text-amber-400">{selectedVuln.sla_description}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Exploit Prediction (EPSS):</span>
                <span className="font-semibold text-red-400">{(selectedVuln.epss_probability * 100).toFixed(1)}%</span>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Automated SOAR Action
                </label>
                <select
                  value={remediationAction}
                  onChange={(e) => setRemediationAction(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="APPLY_VIRTUAL_PATCH">APPLY_VIRTUAL_PATCH (Deploy WAF/Envoy Filter)</option>
                  <option value="ISOLATE_HOST">ISOLATE_HOST (Quarantine Host into Micro-segment)</option>
                  <option value="HOST_UPGRADE">HOST_UPGRADE (Automated Package Upgrade / Hotfix)</option>
                  <option value="ACCEPT_RISK">ACCEPT_RISK (Document Risk Acceptance with CISO)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Resolution Notes & Audit Justification
                </label>
                <textarea
                  rows={3}
                  value={remediationNotes}
                  onChange={(e) => setRemediationNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-sm text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={() => setSelectedVuln(null)}
                  className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-xl text-sm transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleRemediateSubmit}
                  disabled={isRemediating}
                  className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl text-sm transition shadow-lg flex items-center justify-center gap-2"
                >
                  {isRemediating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  Execute Remediation
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

