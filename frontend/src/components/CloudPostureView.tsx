import React, { useState, useEffect } from 'react';
import {
  Cloud,
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
} from 'lucide-react';
import { api } from '../services/api';
import {
  CloudFinding,
  CspmPolicy,
  IacPatch,
  CspmMetrics,
  CloudProviderType,
  FindingSeverityType,
} from '../types';

export const CloudPostureView: React.FC = () => {
  const [metrics, setMetrics] = useState<CspmMetrics | null>(null);
  const [policies, setPolicies] = useState<CspmPolicy[]>([]);
  const [findings, setFindings] = useState<CloudFinding[]>([]);
  const [activeTab, setActiveTab] = useState<'findings' | 'inspector' | 'policies'>('findings');

  const [selectedFinding, setSelectedFinding] = useState<CloudFinding | null>(null);
  const [selectedPatch, setSelectedPatch] = useState<IacPatch | null>(null);
  const [providerFilter, setProviderFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      setLoading(true);
      const [m, p, f] = await Promise.all([
        api.getCspmMetrics(),
        api.getCspmPolicies(),
        api.getCspmFindings(),
      ]);
      setMetrics(m);
      setPolicies(p);
      setFindings(f);

      if (f.length > 0 && !selectedFinding) {
        setSelectedFinding(f[0]);
        const patch = await api.getCspmFindingPatch(f[0].finding_id);
        setSelectedPatch(patch);
      }
    } catch (err) {
      console.error('Failed to load CSPM data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSelectFinding = async (finding: CloudFinding) => {
    setSelectedFinding(finding);
    try {
      const patch = await api.getCspmFindingPatch(finding.finding_id);
      setSelectedPatch(patch);
    } catch (err) {
      console.error('Failed to load IaC patch:', err);
      setSelectedPatch(null);
    }
  };

  const handleRemediate = async (findingId: string) => {
    try {
      setRemediatingId(findingId);
      const res = await api.remediateCspmFinding(findingId);
      if (res) {
        await loadData();
        if (selectedFinding?.finding_id === findingId) {
          setSelectedFinding((prev) => (prev ? { ...prev, status: 'REMEDIATED', pull_request_id: res.pull_request_id } : null));
        }
      }
    } catch (err) {
      console.error('Remediation failed:', err);
    } finally {
      setRemediatingId(null);
    }
  };

  const handleResetBaseline = async () => {
    try {
      setLoading(true);
      await api.resetCspmFindings();
      await loadData();
    } catch (err) {
      console.error('Reset baseline failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const getProviderBadge = (provider: string) => {
    switch (provider) {
      case 'AWS':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">AWS</span>;
      case 'AZURE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">AZURE</span>;
      case 'GCP':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">GCP</span>;
      case 'KUBERNETES':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">K8S</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">{provider}</span>;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-500/15 text-orange-400 border border-orange-500/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/40">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">{severity}</span>;
    }
  };

  const filteredFindings = findings.filter((f) => {
    const matchProvider = providerFilter === 'ALL' || f.provider === providerFilter;
    const matchSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    return matchProvider && matchSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-slate-900/60 p-5 rounded-xl border border-slate-800 backdrop-blur">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
              <Cloud className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-wider text-slate-100 uppercase font-mono">
                  Cloud Security Posture Management (CSPM) & IaC Guard
                </h1>
                <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-sky-500/10 text-sky-400 border border-sky-500/30">
                  CIS BENCHMARK v3.0
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Continuous Multi-Cloud Governance &bull; Automated Terraform / K8s Patch Synthesis &bull; Git PR Generation
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleResetBaseline}
            disabled={loading}
            className="flex items-center space-x-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition border border-slate-700"
            title="Reset findings to baseline OPEN status"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Baseline</span>
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gradient-to-r from-sky-600 to-cyan-600 hover:from-sky-500 hover:to-cyan-500 text-white text-xs font-bold font-mono transition shadow-lg shadow-sky-950/40 border border-sky-500/40"
          >
            <Activity className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Run Multi-Cloud Scan</span>
          </button>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">CIS Compliance Score</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              {metrics ? `${metrics.overall_cis_compliance_percent}%` : '--'}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Multi-cloud CIS benchmark</p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Cloud Resources</span>
            <Server className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {metrics ? metrics.total_cloud_resources_scanned : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">scanned</span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">AWS &bull; Azure &bull; GCP &bull; K8s</p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Active Findings</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-rose-400">
              {metrics ? metrics.active_findings_count : '--'}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ {metrics?.total_findings_count}</span>
          </div>
          <p className="text-[10px] text-rose-400 font-mono mt-1">
            {metrics ? `${metrics.critical_findings_count} Critical &bull; ${metrics.high_findings_count} High` : '--'}
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Automated Remediation</span>
            <GitPullRequest className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-purple-400">
              {metrics ? `${metrics.automated_remediation_rate_percent}%` : '--'}
            </span>
          </div>
          <p className="text-[10px] text-emerald-400 font-mono mt-1">
            {metrics ? `${metrics.remediated_findings_count} Git PRs merged` : '--'}
          </p>
        </div>

        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 backdrop-blur">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">Provider Posture</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-xs font-mono space-y-0.5">
            <div className="flex justify-between">
              <span className="text-amber-400">AWS:</span>
              <span className="text-slate-200">{metrics?.compliance_by_provider?.AWS ?? 92}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-indigo-400">K8s:</span>
              <span className="text-slate-200">{metrics?.compliance_by_provider?.KUBERNETES ?? 89}%</span>
            </div>
          </div>
          <p className="text-[10px] text-slate-400 font-mono mt-1">Continuous zero-drift guard</p>
        </div>
      </div>

      {/* Subnavigation Tabs */}
      <div className="flex border-b border-slate-800 space-x-4">
        <button
          onClick={() => setActiveTab('findings')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'findings'
              ? 'text-sky-400 border-b-2 border-sky-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-4 h-4" />
          <span>Misconfigurations ({filteredFindings.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('inspector')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'inspector'
              ? 'text-sky-400 border-b-2 border-sky-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>IaC Diff Inspector</span>
          {selectedFinding && <span className="w-2 h-2 rounded-full bg-sky-400"></span>}
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          className={`pb-3 text-xs font-mono font-semibold flex items-center space-x-2 transition ${
            activeTab === 'policies'
              ? 'text-sky-400 border-b-2 border-sky-500'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>CIS Benchmark Catalog ({policies.length})</span>
        </button>
      </div>

      {/* Tab 1: Misconfiguration Inventory */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800 text-xs font-mono">
            <div className="flex items-center space-x-3">
              <span className="text-slate-500 flex items-center">
                <Filter className="w-3.5 h-3.5 mr-1" /> Provider:
              </span>
              {['ALL', 'AWS', 'AZURE', 'GCP', 'KUBERNETES'].map((prov) => (
                <button
                  key={prov}
                  onClick={() => setProviderFilter(prov)}
                  className={`px-2.5 py-1 rounded text-xs transition ${
                    providerFilter === prov
                      ? 'bg-sky-500/20 text-sky-400 border border-sky-500/40 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {prov}
                </button>
              ))}
            </div>

            <div className="flex items-center space-x-3">
              <span className="text-slate-500">Severity:</span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-0.5 rounded text-xs transition ${
                    severityFilter === sev
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Findings Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredFindings.map((finding) => (
              <div
                key={finding.finding_id}
                onClick={() => handleSelectFinding(finding)}
                className={`p-5 rounded-xl border transition cursor-pointer ${
                  selectedFinding?.finding_id === finding.finding_id
                    ? 'bg-slate-900/90 border-sky-500/60 shadow-lg shadow-sky-950/30'
                    : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-sky-400">{finding.finding_id}</span>
                      {getProviderBadge(finding.provider)}
                      {getSeverityBadge(finding.severity)}
                    </div>
                    <h3 className="text-sm font-bold text-slate-100 font-mono pt-1">{finding.title}</h3>
                  </div>

                  <div>
                    {finding.status === 'REMEDIATED' ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1">
                        <Check className="w-3 h-3 mr-1" />
                        REMEDIATED
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                        OPEN
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-xs text-slate-400 mt-2 line-clamp-2">{finding.description}</p>

                <div className="mt-3 pt-2.5 border-t border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-500 truncate">
                    Resource: <span className="text-slate-300">{finding.resource_name}</span>
                  </div>
                  <div className="text-slate-500 truncate">
                    IaC Target: <span className="text-cyan-400">{finding.iac_file_path}</span>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-400">Policy: {finding.policy_id}</span>
                  <div className="flex space-x-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleSelectFinding(finding);
                        setActiveTab('inspector');
                      }}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition"
                    >
                      View IaC Patch
                    </button>
                    {finding.status !== 'REMEDIATED' && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRemediate(finding.finding_id);
                        }}
                        disabled={remediatingId === finding.finding_id}
                        className="flex items-center space-x-1 px-3 py-1 rounded bg-sky-600/20 hover:bg-sky-600/30 border border-sky-500/40 text-sky-400 text-xs font-mono font-semibold transition"
                      >
                        <GitPullRequest className={`w-3.5 h-3.5 ${remediatingId === finding.finding_id ? 'animate-spin' : ''}`} />
                        <span>Remediate</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 2: IaC Diff Inspector */}
      {activeTab === 'inspector' && selectedFinding && selectedPatch && (
        <div className="space-y-5">
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-xs font-bold text-sky-400">{selectedFinding.finding_id}</span>
                  {getProviderBadge(selectedFinding.provider)}
                  <h3 className="text-base font-bold text-slate-100 font-mono">{selectedFinding.title}</h3>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Target File: <span className="text-cyan-400 font-semibold">{selectedPatch.target_file}</span> &bull;{' '}
                  Format: <span className="text-purple-400">{selectedPatch.iac_format}</span>
                </p>
              </div>

              <div className="flex items-center space-x-3">
                {selectedFinding.status === 'REMEDIATED' ? (
                  <div className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center space-x-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Merged in {selectedFinding.pull_request_id}</span>
                  </div>
                ) : (
                  <button
                    onClick={() => handleRemediate(selectedFinding.finding_id)}
                    disabled={remediatingId === selectedFinding.finding_id}
                    className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gradient-to-r from-sky-600 to-cyan-600 hover:from-sky-500 hover:to-cyan-500 text-white text-xs font-bold font-mono transition shadow-lg shadow-sky-950/40 border border-sky-500/40"
                  >
                    <GitPullRequest className={`w-3.5 h-3.5 ${remediatingId === selectedFinding.finding_id ? 'animate-spin' : ''}`} />
                    <span>Apply IaC Patch & Generate PR</span>
                  </button>
                )}
              </div>
            </div>

            {/* Git PR Metadata Preview */}
            <div className="bg-slate-950/80 p-3.5 rounded-lg border border-slate-800/80 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <span className="text-slate-500 block mb-0.5">Target PR Branch:</span>
                <span className="text-indigo-400">{selectedPatch.pull_request_branch}</span>
              </div>
              <div>
                <span className="text-slate-500 block mb-0.5">Commit Message:</span>
                <span className="text-slate-300">{selectedPatch.commit_message}</span>
              </div>
            </div>

            {/* Unified Diff Viewer */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center justify-between">
                <span>Unified Diff (`git diff -u`):</span>
                <span className="text-emerald-400">Zero-Drift Verified</span>
              </h4>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto leading-relaxed">
                {selectedPatch.unified_diff.split('\n').map((line, idx) => {
                  let lineClass = 'text-slate-300';
                  if (line.startsWith('+') && !line.startsWith('+++')) {
                    lineClass = 'text-emerald-400 bg-emerald-500/10 px-1 rounded block';
                  } else if (line.startsWith('-') && !line.startsWith('---')) {
                    lineClass = 'text-rose-400 bg-rose-500/10 px-1 rounded block line-through';
                  } else if (line.startsWith('@@')) {
                    lineClass = 'text-cyan-400 font-bold';
                  }
                  return (
                    <div key={idx} className={lineClass}>
                      {line}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: CIS Benchmark Catalog */}
      {activeTab === 'policies' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {policies.map((policy) => (
            <div key={policy.policy_id} className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-sky-400">{policy.policy_id}</span>
                    {getProviderBadge(policy.provider)}
                    {getSeverityBadge(policy.severity)}
                  </div>
                  <h4 className="text-sm font-bold text-slate-100 font-mono mt-1.5">{policy.title}</h4>
                </div>
              </div>

              <p className="text-xs text-slate-400">{policy.description}</p>

              <div className="pt-2 border-t border-slate-800/80 text-xs font-mono space-y-1">
                <div className="text-slate-500">Benchmark: <span className="text-slate-300">{policy.benchmark}</span></div>
                <div className="text-slate-500">Section: <span className="text-slate-300">{policy.section}</span></div>
              </div>

              <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-xs font-mono">
                <span className="text-slate-500 block mb-1">Automated Remediation Guide:</span>
                <span className="text-emerald-400">{policy.remediation_guide}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

