import React, { useState, useEffect } from 'react';
import {
  Package,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  FileCode,
  GitPullRequest,
  Check,
  Terminal,
  ExternalLink,
  Layers,
  Cpu,
  Server,
  Lock,
  Activity,
  Code2,
  Filter,
  Download,
  Flame,
  Bug,
  Scale,
  Radar,
  ArrowUpRight,
} from 'lucide-react';
import { api } from '../services/api';
import {
  SbomSummary,
  PackageComponent,
  ScaVulnerability,
  SupplyChainThreat,
  LicenseRisk,
  ScaRemediationPatch,
  ScaMetrics,
} from '../types';

export const SupplyChainView: React.FC = () => {
  const [metrics, setMetrics] = useState<ScaMetrics | null>(null);
  const [sboms, setSboms] = useState<SbomSummary[]>([]);
  const [components, setComponents] = useState<PackageComponent[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<ScaVulnerability[]>([]);
  const [threats, setThreats] = useState<SupplyChainThreat[]>([]);
  const [licenses, setLicenses] = useState<LicenseRisk[]>([]);

  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'components' | 'threats' | 'licenses'>('vulnerabilities');
  const [selectedVuln, setSelectedVuln] = useState<ScaVulnerability | null>(null);
  const [selectedPatch, setSelectedPatch] = useState<ScaRemediationPatch | null>(null);
  const [selectedSbomId, setSelectedSbomId] = useState<string>('ALL');

  const [ecosystemFilter, setEcosystemFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [cisaKevOnly, setCisaKevOnly] = useState<boolean>(false);

  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [exportLoading, setExportLoading] = useState(false);
  const [exportedJson, setExportedJson] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [m, s, c, v, t, l] = await Promise.all([
        api.getScaMetrics(),
        api.getSboms(),
        api.getScaComponents(),
        api.getScaVulnerabilities(),
        api.getScaThreats(),
        api.getScaLicenses(),
      ]);
      setMetrics(m);
      setSboms(s);
      setComponents(c);
      setVulnerabilities(v);
      setThreats(t);
      setLicenses(l);

      if (v.length > 0 && !selectedVuln) {
        setSelectedVuln(v[0]);
        const patch = await api.getScaPatch(v[0].vuln_id);
        setSelectedPatch(patch);
      }
    } catch (err) {
      console.error('Failed to load SCA data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSelectVuln = async (vuln: ScaVulnerability) => {
    setSelectedVuln(vuln);
    try {
      const patch = await api.getScaPatch(vuln.vuln_id);
      setSelectedPatch(patch);
    } catch (err) {
      console.error('Failed to load patch:', err);
      setSelectedPatch(null);
    }
  };

  const handleRemediate = async (vulnId: string) => {
    try {
      setRemediatingId(vulnId);
      const res = await api.remediateSca(vulnId);
      if (res && res.status === 'SUCCESS') {
        await loadData();
        // Keep active selection updated
        const updated = await api.getScaVulnerabilities();
        const cur = updated.find((x) => x.vuln_id === vulnId);
        if (cur) setSelectedVuln(cur);
      }
    } catch (err) {
      console.error('Remediation failed:', err);
    } finally {
      setRemediatingId(null);
    }
  };

  const handleExportCycloneDx = async (sbomId: string) => {
    try {
      setExportLoading(true);
      const actualId = sbomId === 'ALL' ? (sboms[0]?.sbom_id || 'SBOM-CORE-API') : sbomId;
      const doc = await api.exportCycloneDxSbom(actualId);
      if (doc) {
        const jsonStr = JSON.stringify(doc, null, 2);
        setExportedJson(jsonStr);

        // Auto-download file
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${doc.metadata?.component?.name || 'cyclonedx'}-sbom-v1.5.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('Failed to export CycloneDX SBOM:', err);
    } finally {
      setExportLoading(false);
    }
  };

  // Filtered lists
  const filteredVulns = vulnerabilities.filter((v) => {
    if (ecosystemFilter !== 'ALL' && v.ecosystem !== ecosystemFilter) return false;
    if (severityFilter !== 'ALL' && v.severity !== severityFilter) return false;
    if (cisaKevOnly && !v.cisa_kev) return false;
    return true;
  });

  const filteredComponents = components.filter((c) => {
    if (selectedSbomId !== 'ALL' && c.sbom_id !== selectedSbomId) return false;
    if (ecosystemFilter !== 'ALL' && c.ecosystem !== ecosystemFilter) return false;
    return true;
  });

  if (loading && !metrics) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-slate-400 font-mono text-sm">Evaluating Software Supply Chain & CycloneDX SBOMs...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header & Export Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-6 rounded-xl border border-slate-800">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-teal-500/10 border border-teal-500/30 text-teal-400">
              <Package className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
                <span>Autonomous Software Supply Chain & SBOM Governance</span>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-teal-500/10 text-teal-400 border border-teal-500/30 font-mono font-normal">
                  CycloneDX v1.5 / SPDX
                </span>
              </h2>
              <p className="text-sm text-slate-400 font-mono">
                Continuous open-source dependency auditing, EPSS exploit prediction, CISA KEV detection & automated Git PR patching
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => handleExportCycloneDx(selectedSbomId)}
            disabled={exportLoading}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-teal-600/20 border border-teal-500/40 text-teal-300 hover:bg-teal-600/30 text-xs font-mono font-semibold transition"
          >
            <Download className="w-4 h-4" />
            <span>{exportLoading ? 'Exporting...' : 'Export CycloneDX JSON'}</span>
          </button>
          <button
            onClick={loadData}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition border border-slate-700"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Rescan Dependencies</span>
          </button>
        </div>
      </div>

      {/* KPI Metrics Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Health Score</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span
              className={`text-2xl font-bold font-mono ${
                (metrics?.health_score || 0) >= 85
                  ? 'text-emerald-400'
                  : (metrics?.health_score || 0) >= 70
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {metrics?.health_score || 0}%
            </span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono mt-1">Weighted Supply Chain Posture</span>
        </div>

        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Packages Tracked</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">{metrics?.total_components || 0}</span>
            <span className="text-xs text-slate-500 font-mono">({metrics?.direct_components} direct)</span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono mt-1">PyPI, npm, Go modules</span>
        </div>

        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Open CVEs</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span
              className={`text-2xl font-bold font-mono ${
                (metrics?.open_vulnerabilities || 0) > 0 ? 'text-amber-400' : 'text-emerald-400'
              }`}
            >
              {metrics?.open_vulnerabilities || 0}
            </span>
            <span className="text-xs text-rose-400 font-mono">({metrics?.critical_vulnerabilities} crit)</span>
          </div>
          <span className="text-[11px] text-slate-500 font-mono mt-1">Known security flaws</span>
        </div>

        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">CISA KEV Exploited</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span
              className={`text-2xl font-bold font-mono ${
                (metrics?.cisa_kev_active || 0) > 0 ? 'text-rose-400 animate-pulse' : 'text-emerald-400'
              }`}
            >
              {metrics?.cisa_kev_active || 0}
            </span>
          </div>
          <span className="text-[11px] text-rose-500 font-mono mt-1">Active in-the-wild exploitation</span>
        </div>

        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Supply Chain Threats</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-purple-400">{metrics?.active_threats_count || 0}</span>
          </div>
          <span className="text-[11px] text-purple-400/80 font-mono mt-1">Typosquatting & scripts</span>
        </div>

        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Remediation Rate</span>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">{metrics?.remediation_rate || 0}%</span>
          </div>
          <span className="text-[11px] text-emerald-500/80 font-mono mt-1">Autonomous PR patches</span>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('vulnerabilities')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'vulnerabilities'
              ? 'bg-teal-500/10 text-teal-400 border border-teal-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Bug className="w-4 h-4" />
          <span>Vulnerabilities & EPSS ({vulnerabilities.filter((v) => v.status === 'OPEN').length})</span>
        </button>

        <button
          onClick={() => setActiveTab('components')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'components'
              ? 'bg-teal-500/10 text-teal-400 border border-teal-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>SBOM Components ({components.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('threats')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'threats'
              ? 'bg-teal-500/10 text-teal-400 border border-teal-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Radar className="w-4 h-4" />
          <span>Supply Chain Threats ({threats.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('licenses')}
          className={`px-4 py-2 rounded-lg text-xs font-mono font-semibold transition flex items-center space-x-2 ${
            activeTab === 'licenses'
              ? 'bg-teal-500/10 text-teal-400 border border-teal-500/30'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Scale className="w-4 h-4" />
          <span>License Compliance ({licenses.length})</span>
        </button>
      </div>

      {/* TAB 1: Vulnerabilities & Autonomous IaC Patch Inspector */}
      {activeTab === 'vulnerabilities' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Vulnerability List (7 cols) */}
          <div className="lg:col-span-7 space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/40 p-3 rounded-lg border border-slate-800/80 text-xs font-mono">
              <div className="flex items-center space-x-2">
                <span className="text-slate-400">Ecosystem:</span>
                {['ALL', 'pypi', 'npm', 'golang'].map((eco) => (
                  <button
                    key={eco}
                    onClick={() => setEcosystemFilter(eco)}
                    className={`px-2.5 py-1 rounded ${
                      ecosystemFilter === eco
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                    }`}
                  >
                    {eco}
                  </button>
                ))}
              </div>

              <div className="flex items-center space-x-3">
                <label className="flex items-center space-x-1.5 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={cisaKevOnly}
                    onChange={(e) => setCisaKevOnly(e.target.checked)}
                    className="rounded bg-slate-800 border-slate-700 text-rose-500 focus:ring-0"
                  />
                  <span className="text-rose-400 font-semibold">CISA KEV Only</span>
                </label>
              </div>
            </div>

            {/* List */}
            <div className="space-y-3">
              {filteredVulns.map((v) => {
                const isSelected = selectedVuln?.vuln_id === v.vuln_id;
                const isRemediated = v.status === 'REMEDIATED';

                return (
                  <div
                    key={v.vuln_id}
                    onClick={() => handleSelectVuln(v)}
                    className={`p-4 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-slate-800/80 border-cyan-500/50 shadow-lg shadow-cyan-950/20'
                        : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-sm text-slate-100 font-mono">{v.cve_id}</span>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                              v.severity === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                                : v.severity === 'HIGH'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                : 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                            }`}
                          >
                            CVSS {v.cvss_score.toFixed(1)} {v.severity}
                          </span>

                          {v.cisa_kev && (
                            <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                              CISA KEV
                            </span>
                          )}

                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                              isRemediated
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : 'bg-amber-500/10 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {v.status}
                          </span>
                        </div>

                        <h4 className="text-xs text-slate-300 mt-1 font-medium">{v.title}</h4>

                        <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400">
                          <span>
                            Package: <strong className="text-cyan-300">{v.package_name}</strong>
                          </span>
                          <span>
                            Installed: <span className="text-rose-400">{v.installed_version}</span> &rarr; Fix:{' '}
                            <span className="text-emerald-400">{v.fixed_version}</span>
                          </span>
                          <span className="uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                            {v.ecosystem}
                          </span>
                        </div>
                      </div>

                      {/* EPSS Bar */}
                      <div className="text-right min-w-[80px]">
                        <span className="text-[10px] text-slate-400 font-mono block">EPSS Exploit Prob</span>
                        <span className="text-sm font-bold font-mono text-purple-300">
                          {(v.epss_score * 100).toFixed(1)}%
                        </span>
                        <div className="w-20 bg-slate-800 h-1.5 rounded-full mt-1 overflow-hidden">
                          <div
                            className="bg-gradient-to-r from-purple-500 to-rose-500 h-full rounded-full"
                            style={{ width: `${Math.min(100, v.epss_score * 100)}%` }}
                          />
                        </div>
                      </div>
                    </div>

                    {/* Reachability Callout */}
                    <div className="mt-3 p-2 rounded bg-slate-950/60 border border-slate-800/80 text-[11px] font-mono flex items-center justify-between">
                      <span className="text-slate-400">
                        Call-Graph Reachability:{' '}
                        <strong
                          className={
                            v.reachability === 'DIRECT_EXECUTION_PATH'
                              ? 'text-rose-400'
                              : v.reachability === 'TRANSITIVE_CALLABLE'
                              ? 'text-amber-400'
                              : 'text-slate-500'
                          }
                        >
                          {v.reachability}
                        </strong>
                      </span>
                      <span className="text-slate-500 text-[10px]">{v.reachability_rationale}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Autonomous Dependency Bump & PR Inspector (5 cols) */}
          <div className="lg:col-span-5 space-y-4">
            {selectedVuln && selectedPatch ? (
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 sticky top-24">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <FileCode className="w-5 h-5 text-cyan-400" />
                    <h3 className="text-sm font-bold text-slate-100 font-mono">Autonomous Dependency Patch</h3>
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                    {selectedPatch.manifest_file}
                  </span>
                </div>

                <div>
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider">Automated PR Branch</h4>
                  <div className="mt-1 flex items-center space-x-2 text-xs font-mono text-teal-400 bg-slate-950 px-3 py-1.5 rounded border border-slate-800">
                    <GitPullRequest className="w-3.5 h-3.5" />
                    <span>{selectedPatch.git_branch}</span>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider">PR Title & Commit</h4>
                  <p className="text-xs text-slate-200 font-mono mt-1 bg-slate-950 p-2 rounded border border-slate-800">
                    {selectedPatch.pr_title}
                  </p>
                </div>

                {/* Unified Diff Viewer */}
                <div>
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                    <span>Synthesized Unified Diff</span>
                    <span className="text-[10px] text-emerald-400">diff -u verified</span>
                  </h4>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono overflow-x-auto leading-relaxed">
                    {selectedPatch.unified_diff.split('\n').map((line, idx) => {
                      let colorClass = 'text-slate-400';
                      if (line.startsWith('+') && !line.startsWith('+++')) colorClass = 'text-emerald-400 bg-emerald-950/30';
                      else if (line.startsWith('-') && !line.startsWith('---')) colorClass = 'text-rose-400 bg-rose-950/30';
                      else if (line.startsWith('@@')) colorClass = 'text-cyan-400 font-bold';
                      return (
                        <div key={idx} className={colorClass}>
                          {line}
                        </div>
                      );
                    })}
                  </pre>
                </div>

                {/* Remediation Action */}
                <div className="pt-2">
                  {selectedVuln.status === 'REMEDIATED' ? (
                    <div className="flex items-center space-x-2 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>PR Merged & Vulnerability Remediated Autonomously</span>
                    </div>
                  ) : (
                    <button
                      onClick={() => handleRemediate(selectedVuln.vuln_id)}
                      disabled={remediatingId === selectedVuln.vuln_id}
                      className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-mono text-xs font-bold transition shadow-lg shadow-teal-900/30"
                    >
                      {remediatingId === selectedVuln.vuln_id ? (
                        <>
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                          <span>Applying Automated PR & Verifying Build...</span>
                        </>
                      ) : (
                        <>
                          <GitPullRequest className="w-4 h-4" />
                          <span>Apply Automated PR & Upgrade Dependency</span>
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-8 text-center text-slate-500 font-mono text-xs">
                Select a vulnerability on the left to inspect its autonomous dependency patch.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SBOM & Components Explorer */}
      {activeTab === 'components' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/40 p-4 rounded-xl border border-slate-800 text-xs font-mono">
            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Target SBOM:</span>
              <select
                value={selectedSbomId}
                onChange={(e) => setSelectedSbomId(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 rounded px-3 py-1 text-xs focus:ring-0"
              >
                <option value="ALL">All Applications & Repositories</option>
                {sboms.map((s) => (
                  <option key={s.sbom_id} value={s.sbom_id}>
                    {s.name} ({s.version}) - {s.ecosystem}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Ecosystem:</span>
              {['ALL', 'pypi', 'npm', 'golang'].map((eco) => (
                <button
                  key={eco}
                  onClick={() => setEcosystemFilter(eco)}
                  className={`px-2.5 py-1 rounded ${
                    ecosystemFilter === eco
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  {eco}
                </button>
              ))}
            </div>
          </div>

          <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-800/60 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-3">Package Component</th>
                  <th className="p-3">Version</th>
                  <th className="p-3">Ecosystem</th>
                  <th className="p-3">Canonical PURL</th>
                  <th className="p-3">Depth</th>
                  <th className="p-3">License</th>
                  <th className="p-3 text-right">CVE Count</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredComponents.map((c) => (
                  <tr key={c.component_id} className="hover:bg-slate-800/30 transition">
                    <td className="p-3 font-semibold text-slate-200">{c.name}</td>
                    <td className="p-3 text-cyan-400">{c.version}</td>
                    <td className="p-3 uppercase text-slate-400 text-[10px]">{c.ecosystem}</td>
                    <td className="p-3 text-slate-500 font-mono text-[11px] truncate max-w-[200px]" title={c.purl}>
                      {c.purl}
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] ${
                          c.is_direct
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20 font-bold'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {c.is_direct ? 'DIRECT' : 'TRANSITIVE'}
                      </span>
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] ${
                          c.license_risk === 'HIGH_RISK'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}
                      >
                        {c.license}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      {c.vulnerabilities_count > 0 ? (
                        <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold">
                          {c.vulnerabilities_count} CVEs
                        </span>
                      ) : (
                        <span className="text-emerald-400 flex items-center justify-end space-x-1">
                          <Check className="w-3.5 h-3.5" />
                          <span>Clean</span>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Supply Chain Threats & Anomaly Radar */}
      {activeTab === 'threats' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 text-xs font-mono text-purple-300 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Radar className="w-5 h-5 text-purple-400 animate-spin" />
              <span>
                Active Supply Chain Threat Radar: Scanning package registries for typosquatting, dependency confusion & malicious install hooks.
              </span>
            </div>
            <span className="px-2.5 py-1 rounded bg-purple-500/20 border border-purple-500/40 font-bold">
              {threats.length} THREATS NEUTRALIZED
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {threats.map((t) => (
              <div key={t.threat_id} className="p-5 rounded-xl bg-slate-900/60 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold">
                    {t.type}
                  </span>
                  <span className="text-xs font-mono font-bold text-rose-400">Risk Score: {t.risk_score}/100</span>
                </div>

                <div>
                  <h3 className="font-mono font-bold text-slate-100 text-sm">{t.package_name}</h3>
                  <p className="text-xs text-slate-400 mt-1 font-mono">{t.detection_reason}</p>
                </div>

                <div className="text-[11px] font-mono text-slate-500 space-y-1 pt-2 border-t border-slate-800">
                  <div>Detected in: <span className="text-slate-300">{t.detected_in}</span></div>
                  <div>Target package: <span className="text-cyan-400">{t.target_package}</span></div>
                  <div>Status: <span className="text-emerald-400 font-bold">{t.status}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: License Compliance */}
      {activeTab === 'licenses' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs font-mono text-amber-300">
            Open Source License & Legal Contamination Engine: Evaluates copyleft licenses (GPL, AGPL) that may force disclosure of proprietary IP upon distribution or SaaS hosting.
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {licenses.map((lic) => (
              <div key={lic.risk_id} className="p-5 rounded-xl bg-slate-900/60 border border-amber-500/40 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Scale className="w-4 h-4 text-amber-400" />
                    <span className="font-mono font-bold text-slate-100 text-sm">{lic.package_name}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40">
                    {lic.license} ({lic.risk_level})
                  </span>
                </div>

                <p className="text-xs text-slate-300 font-mono">{lic.commercial_impact}</p>

                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300">
                  <strong>Recommendation:</strong> {lic.recommendation}
                </div>

                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-2 border-t border-slate-800">
                  <span>Category: {lic.category}</span>
                  <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-bold">
                    {lic.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

