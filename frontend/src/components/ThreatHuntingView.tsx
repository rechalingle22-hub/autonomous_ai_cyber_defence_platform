import React, { useState, useEffect } from 'react';
import {
  Search,
  Compass,
  Code2,
  ShieldAlert,
  CheckCircle2,
  Terminal,
  Copy,
  Play,
  RefreshCw,
  X,
  Zap,
  FileCode,
  Layers,
  Activity,
  Clock,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../services/api';
import {
  ThreatHuntingMetrics,
  HuntHypothesis,
  HuntExecutionResult,
  DetectionRule,
  RuleFormat,
  RuleStatus,
} from '../types';

export const ThreatHuntingView: React.FC = () => {
  const [metrics, setMetrics] = useState<ThreatHuntingMetrics | null>(null);
  const [hypotheses, setHypotheses] = useState<HuntHypothesis[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [huntHistory, setHuntHistory] = useState<HuntExecutionResult[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'hypotheses' | 'rules' | 'history'>('hypotheses');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Active Hunt Runner State
  const [selectedHypothesis, setSelectedHypothesis] = useState<HuntHypothesis | null>(null);
  const [timeWindowHours, setTimeWindowHours] = useState<number>(24);
  const [isExecutingHunt, setIsExecutingHunt] = useState<boolean>(false);
  const [lastHuntResult, setLastHuntResult] = useState<HuntExecutionResult | null>(null);

  // Rule Generation Modal State
  const [isRuleModalOpen, setIsRuleModalOpen] = useState<boolean>(false);
  const [generateFormat, setGenerateFormat] = useState<RuleFormat>('SIGMA_YAML');
  const [generateTitle, setGenerateTitle] = useState<string>('');
  const [generateSeverity, setGenerateSeverity] = useState<string>('high');
  const [isGeneratingRule, setIsGeneratingRule] = useState<boolean>(false);

  // Rule Filter
  const [ruleFormatFilter, setRuleFormatFilter] = useState<string>('ALL');
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [m, h, r, hist] = await Promise.all([
        api.getThreatHuntingMetrics(),
        api.getHuntHypotheses(),
        api.getDetectionRules(),
        api.getHuntHistory(),
      ]);
      if (m) setMetrics(m);
      setHypotheses(h);
      setRules(r);
      setHuntHistory(hist);
      if (h.length > 0 && !selectedHypothesis) {
        setSelectedHypothesis(h[0]);
      }
    } catch {
      setActionMessage('Failed to connect to Threat Hunting service');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleExecuteHunt = async () => {
    if (!selectedHypothesis) return;
    setIsExecutingHunt(true);
    try {
      const result = await api.executeHunt(selectedHypothesis.id, timeWindowHours);
      if (result) {
        setLastHuntResult(result);
        setActionMessage(
          `Hunt executed! Discovered ${result.findings_count} IOCs with ${result.confidence_score}% confidence.`
        );
        setTimeout(() => setActionMessage(null), 5000);
        await loadData();
      }
    } catch {
      setActionMessage('Threat hunt execution failed');
    } finally {
      setIsExecutingHunt(false);
    }
  };

  const handleOpenRuleModal = (format: RuleFormat) => {
    setGenerateFormat(format);
    setGenerateTitle(
      format === 'SIGMA_YAML'
        ? `Sigma: ${selectedHypothesis?.title || 'Behavioral Threat'}`
        : `Hunt_${selectedHypothesis?.id || 'Hyp'}_PayloadPattern`
    );
    setIsRuleModalOpen(true);
  };

  const handleGenerateRuleSubmit = async () => {
    if (!selectedHypothesis) return;
    setIsGeneratingRule(true);
    try {
      const newRule = await api.generateDetectionRule(
        selectedHypothesis.id,
        generateFormat,
        generateTitle,
        generateSeverity
      );
      if (newRule) {
        setActionMessage(`Synthesized ${generateFormat} rule '${newRule.title}' successfully!`);
        setTimeout(() => setActionMessage(null), 5000);
        setIsRuleModalOpen(false);
        setActiveTab('rules');
        await loadData();
      }
    } catch {
      setActionMessage('Failed to synthesize detection rule');
    } finally {
      setIsGeneratingRule(false);
    }
  };

  const handleDeployRule = async (ruleId: string) => {
    try {
      const deployed = await api.deployDetectionRule(ruleId);
      if (deployed) {
        setActionMessage(`Detection rule '${deployed.title}' is now DEPLOYED_ACTIVE on all detection nodes!`);
        setTimeout(() => setActionMessage(null), 5000);
        await loadData();
      }
    } catch {
      setActionMessage('Failed to deploy detection rule');
    }
  };

  const handleCopyCode = (ruleId: string, content: string) => {
    navigator.clipboard.writeText(content);
    setCopiedRuleId(ruleId);
    setTimeout(() => setCopiedRuleId(null), 2500);
  };

  const filteredRules = rules.filter((r) => {
    if (ruleFormatFilter !== 'ALL' && r.format !== ruleFormatFilter) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 p-6 rounded-2xl backdrop-blur shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/20 border border-emerald-500/30 text-emerald-400">
              <Compass className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                Threat Hunting & Autonomous Detection-as-Code
                <span className="px-2.5 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full">
                  Phase 19
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Proactive hypothesis evaluation, Living-off-the-Land discovery, and autonomous Sigma/YARA synthesis
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-sm font-medium transition shadow-sm hover:shadow"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="flex items-center justify-between bg-emerald-950/80 border border-emerald-500/50 text-emerald-200 px-4 py-3 rounded-xl text-sm animate-fade-in shadow-lg">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Validation Rate */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Hypothesis Validation Rate</span>
            <Activity className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? `${metrics.hypothesis_validation_rate}%` : '--'}
            </span>
            <span className="text-xs text-emerald-400 font-semibold">High-Fidelity</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Total Executed Hunts</span>
            <span className="text-slate-200 font-medium">{metrics?.total_hunts_executed || 0} runs</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Hypotheses in Backlog</span>
            <span className="text-slate-200 font-medium">{metrics?.total_hypotheses || 0} active</span>
          </p>
        </div>

        {/* Total Detection Rules */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Detection-as-Code Rules</span>
            <Code2 className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.total_detection_rules : '--'}
            </span>
            <span className="text-xs text-cyan-400 font-semibold">Synthesized</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Sigma YAML Rules</span>
            <span className="text-purple-400 font-semibold">{metrics?.sigma_rules_count || 0} rules</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>YARA Signatures</span>
            <span className="text-cyan-400 font-semibold">{metrics?.yara_rules_count || 0} rules</span>
          </p>
        </div>

        {/* Active Deployed Rules */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Active Deployed Rules</span>
            <ShieldCheck className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.deployed_active_rules : '--'}
            </span>
            <span className="text-xs text-indigo-400 font-semibold">Live in Pipeline</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Pipeline Hot-Reload</span>
            <span className="text-emerald-400 font-medium">Enabled (Sub-5ms)</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Detection Coverage</span>
            <span className="text-slate-200 font-medium">Process, Net, Memory</span>
          </p>
        </div>

        {/* Dwell Time Reduction */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Dwell Time Reduction</span>
            <Clock className="w-5 h-5 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? `${metrics.mean_hunt_dwell_reduction_percent}%` : '--'}
            </span>
            <span className="text-xs text-amber-400 font-semibold">vs Industry Avg</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Proactive vs Reactive</span>
            <span className="text-emerald-400 font-medium">Zero-Day Hunt</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Living-off-the-Land (LotL)</span>
            <span className="text-slate-200 font-medium">100% Fingerprinted</span>
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setActiveTab('hypotheses')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'hypotheses'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Compass className="w-4 h-4" />
          Hypothesis Catalog & Hunt Runner
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {hypotheses.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'rules'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Code2 className="w-4 h-4" />
          Detection-as-Code Repository (Sigma & YARA)
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {rules.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('history')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'history'
              ? 'border-emerald-500 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          Execution History & Findings
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {huntHistory.length}
          </span>
        </button>
      </div>

      {/* TAB 1: HYPOTHESIS CATALOG & HUNT RUNNER */}
      {activeTab === 'hypotheses' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Hypotheses Selection */}
          <div className="lg:col-span-1 space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 px-1">
              Curated Hypotheses Backlog
            </h2>
            <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
              {hypotheses.map((hyp) => (
                <div
                  key={hyp.id}
                  onClick={() => {
                    setSelectedHypothesis(hyp);
                    setLastHuntResult(null);
                  }}
                  className={`p-4 rounded-xl border cursor-pointer transition flex flex-col justify-between ${
                    selectedHypothesis?.id === hyp.id
                      ? 'bg-emerald-950/30 border-emerald-500/60 shadow-lg'
                      : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-bold text-emerald-400">{hyp.id}</span>
                    <span
                      className={`px-2 py-0.5 text-xs font-semibold rounded border ${
                        hyp.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border-red-500/40'
                          : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                      }`}
                    >
                      {hyp.severity}
                    </span>
                  </div>

                  <h3 className="font-semibold text-white text-sm line-clamp-2 mb-1">{hyp.title}</h3>
                  <p className="text-xs text-slate-400 line-clamp-2 mb-2">{hyp.description}</p>

                  <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800/80">
                    <span className="font-mono text-cyan-400">{hyp.mitre_technique}</span>
                    <span className="text-slate-400 font-medium">{hyp.tactic}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right Column: Execution Workbench & Findings */}
          <div className="lg:col-span-2 space-y-5">
            {selectedHypothesis ? (
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur space-y-6">
                {/* Workbench Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-emerald-400">
                        {selectedHypothesis.id}
                      </span>
                      <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        ATT&CK {selectedHypothesis.mitre_technique}
                      </span>
                      <span className="text-xs font-semibold px-2 py-0.5 rounded bg-indigo-950/40 text-indigo-300 border border-indigo-800/40">
                        {selectedHypothesis.tactic}
                      </span>
                    </div>
                    <h2 className="text-xl font-bold text-white mt-1">{selectedHypothesis.title}</h2>
                  </div>

                  {/* Lookback window & Execute */}
                  <div className="flex items-center gap-3">
                    <select
                      value={timeWindowHours}
                      onChange={(e) => setTimeWindowHours(Number(e.target.value))}
                      className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
                    >
                      <option value={12}>Last 12 Hours</option>
                      <option value={24}>Last 24 Hours</option>
                      <option value={48}>Last 48 Hours</option>
                      <option value={168}>Last 7 Days</option>
                    </select>

                    <button
                      onClick={handleExecuteHunt}
                      disabled={isExecutingHunt}
                      className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl text-sm transition shadow-lg flex items-center gap-2 disabled:opacity-50"
                    >
                      {isExecutingHunt ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Evaluating Telemetry...
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 fill-current" />
                          Run Threat Hunt
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Hypothesis Details & Query Logic */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                    <span className="font-semibold text-slate-300">Target Telemetry & Data Sources</span>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedHypothesis.data_sources.map((ds) => (
                        <span key={ds} className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded font-mono">
                          {ds}
                        </span>
                      ))}
                    </div>
                    <p className="text-slate-400 text-xs mt-1">{selectedHypothesis.target_telemetry}</p>
                  </div>

                  <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                    <span className="font-semibold text-slate-300">Hunting Query Logic (Heuristic)</span>
                    <pre className="font-mono text-cyan-400 text-xs overflow-x-auto p-1.5 bg-slate-900 rounded">
                      {selectedHypothesis.query_logic}
                    </pre>
                  </div>
                </div>

                {/* Hunt Findings Section */}
                {lastHuntResult ? (
                  <div className="p-5 rounded-xl bg-slate-950 border border-emerald-500/40 space-y-4 animate-fade-in shadow-xl">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400">
                          <CheckCircle2 className="w-5 h-5" />
                        </div>
                        <div>
                          <h4 className="font-bold text-white text-base">Hunt Validated: Confirmed Findings</h4>
                          <p className="text-xs text-slate-400">
                            Execution ID: <span className="font-mono text-emerald-400">{lastHuntResult.execution_id}</span>
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-2xl font-extrabold text-white">
                          {lastHuntResult.confidence_score}%
                        </span>
                        <span className="px-2 py-0.5 text-xs font-bold rounded bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">
                          {lastHuntResult.confidence_level}
                        </span>
                      </div>
                    </div>

                    {/* Matched IOCs & Affected Hosts */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div>
                        <span className="font-semibold text-slate-300 block mb-1">Matched Indicators & Signatures:</span>
                        <div className="space-y-1">
                          {lastHuntResult.matched_iocs.map((ioc, idx) => (
                            <div key={idx} className="font-mono text-red-400 bg-red-950/20 border border-red-900/40 p-1.5 rounded truncate" title={ioc}>
                              {ioc}
                            </div>
                          ))}
                        </div>
                      </div>

                      <div>
                        <span className="font-semibold text-slate-300 block mb-1">Affected Hosts & Endpoints:</span>
                        <div className="space-y-1">
                          {lastHuntResult.affected_hosts.map((host, idx) => (
                            <div key={idx} className="font-mono text-cyan-300 bg-cyan-950/20 border border-cyan-900/40 p-1.5 rounded truncate" title={host}>
                              {host}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Autonomous Synthesis Triggers */}
                    <div className="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                      <p className="text-xs text-slate-400">
                        Convert this confirmed finding directly into standardized Detection-as-Code:
                      </p>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={() => handleOpenRuleModal('SIGMA_YAML')}
                          className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-xl text-xs transition shadow flex items-center gap-2"
                        >
                          <FileCode className="w-3.5 h-3.5" />
                          Synthesize Sigma Rule
                        </button>
                        <button
                          onClick={() => handleOpenRuleModal('YARA')}
                          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-xl text-xs transition shadow flex items-center gap-2"
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          Synthesize YARA Rule
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="py-10 text-center border border-dashed border-slate-800 rounded-xl">
                    <Search className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    <p className="text-sm font-semibold text-slate-400">Threat Hunt Not Yet Run</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Select time window and click "Run Threat Hunt" to execute behavioral queries against telemetry.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500">Select a hypothesis from the left panel to begin.</div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: DETECTION-AS-CODE REPOSITORY */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 p-4 rounded-xl backdrop-blur">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-400">Filter by Format:</span>
              <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-1">
                {['ALL', 'SIGMA_YAML', 'YARA'].map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setRuleFormatFilter(fmt)}
                    className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                      ruleFormatFilter === fmt
                        ? 'bg-emerald-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {fmt.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <span className="text-xs text-slate-400">
              Showing <span className="font-bold text-white">{filteredRules.length}</span> detection rules
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {filteredRules.map((rule) => (
              <div
                key={rule.id}
                className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 text-xs font-bold rounded ${
                            rule.format === 'SIGMA_YAML'
                              ? 'bg-purple-950/60 text-purple-300 border border-purple-800/40'
                              : 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/40'
                          }`}
                        >
                          {rule.format.replace('_', ' ')}
                        </span>
                        <span className="text-xs font-mono text-emerald-400">{rule.mitre_technique}</span>
                      </div>
                      <h3 className="font-bold text-white text-base mt-1 tracking-tight">{rule.title}</h3>
                    </div>

                    <span
                      className={`px-2 py-0.5 text-xs font-semibold rounded-full border ${
                        rule.status === 'DEPLOYED_ACTIVE'
                          ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                          : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                      }`}
                    >
                      {rule.status.replace('_', ' ')}
                    </span>
                  </div>

                  {/* Code Block */}
                  <div className="relative mt-3 rounded-xl bg-slate-950 border border-slate-800/90 overflow-hidden">
                    <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900/90 border-b border-slate-800/80 text-xs text-slate-400">
                      <span className="font-mono text-xs">{rule.id}</span>
                      <button
                        onClick={() => handleCopyCode(rule.id, rule.content)}
                        className="flex items-center gap-1 hover:text-white transition"
                      >
                        {copiedRuleId === rule.id ? (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400">Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="p-4 font-mono text-xs text-slate-300 overflow-x-auto max-h-[220px] leading-relaxed">
                      {rule.content}
                    </pre>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                  <span className="text-slate-500 font-mono">
                    Author: {rule.author}
                  </span>

                  {rule.status !== 'DEPLOYED_ACTIVE' ? (
                    <button
                      onClick={() => handleDeployRule(rule.id)}
                      className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg text-xs transition shadow flex items-center gap-1.5"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      Deploy to Active Detection
                    </button>
                  ) : (
                    <span className="text-emerald-400 font-medium flex items-center gap-1">
                      <ShieldCheck className="w-4 h-4" /> Enforcing Live
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: EXECUTION HISTORY */}
      {activeTab === 'history' && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-xs font-semibold uppercase tracking-wider text-slate-400">
                  <th className="p-4">Execution ID</th>
                  <th className="p-4">Hypothesis</th>
                  <th className="p-4">Tactic & ATT&CK</th>
                  <th className="p-4">Confidence</th>
                  <th className="p-4">Matched IOCs</th>
                  <th className="p-4">Affected Hosts</th>
                  <th className="p-4">Executed At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-sm">
                {huntHistory.map((h) => (
                  <tr key={h.execution_id} className="hover:bg-slate-800/40 transition">
                    <td className="p-4 font-mono font-bold text-emerald-400 text-xs">
                      {h.execution_id}
                    </td>
                    <td className="p-4">
                      <div className="font-semibold text-white">{h.hypothesis_title}</div>
                      <div className="text-xs text-slate-400 font-mono">{h.hypothesis_id}</div>
                    </td>
                    <td className="p-4">
                      <span className="text-xs font-semibold text-slate-200">{h.tactic}</span>
                      <div className="text-xs text-cyan-400 font-mono">{h.mitre_technique}</div>
                    </td>
                    <td className="p-4">
                      <span
                        className={`font-bold px-2 py-0.5 text-xs rounded-full ${
                          h.confidence_score >= 90
                            ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        }`}
                      >
                        {h.confidence_score}%
                      </span>
                    </td>
                    <td className="p-4">
                      <div className="text-xs text-slate-300 font-mono max-w-xs truncate" title={h.matched_iocs.join(', ')}>
                        {h.matched_iocs.join(', ')}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="text-xs text-cyan-300 font-mono max-w-xs truncate">
                        {h.affected_hosts.join(', ')}
                      </div>
                    </td>
                    <td className="p-4 text-xs text-slate-400 whitespace-nowrap">
                      {new Date(h.executed_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
                {huntHistory.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500">
                      No threat hunt executions recorded yet. Run a hunt from the catalog tab.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* RULE GENERATION MODAL */}
      {isRuleModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5 animate-scale-up">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Code2 className="w-5 h-5 text-emerald-400" />
                  Synthesize Detection-as-Code Rule
                </h3>
                <p className="text-xs text-slate-400 mt-1 font-mono">
                  {selectedHypothesis?.id} &bull; ATT&CK {selectedHypothesis?.mitre_technique}
                </p>
              </div>
              <button
                onClick={() => setIsRuleModalOpen(false)}
                className="text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Detection Rule Format
                </label>
                <select
                  value={generateFormat}
                  onChange={(e) => setGenerateFormat(e.target.value as RuleFormat)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  <option value="SIGMA_YAML">SIGMA_YAML (Generic SIEM/EDR Log Rule)</option>
                  <option value="YARA">YARA (Memory & Binary Signature)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Rule Title
                </label>
                <input
                  type="text"
                  value={generateTitle}
                  onChange={(e) => setGenerateTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Severity Level
                </label>
                <select
                  value={generateSeverity}
                  onChange={(e) => setGenerateSeverity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={() => setIsRuleModalOpen(false)}
                  className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-xl text-sm transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleGenerateRuleSubmit}
                  disabled={isGeneratingRule}
                  className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl text-sm transition shadow-lg flex items-center justify-center gap-2"
                >
                  {isGeneratingRule ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Zap className="w-4 h-4" />
                  )}
                  Synthesize Rule
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

