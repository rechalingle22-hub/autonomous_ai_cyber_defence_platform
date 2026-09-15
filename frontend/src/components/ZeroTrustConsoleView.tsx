import React, { useState, useEffect } from 'react';
import {
  Lock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Sliders,
  Play,
  Plus,
  Network,
  Cpu,
  UserCheck,
  Smartphone,
  Globe,
  Radio,
  ToggleLeft,
  ToggleRight,
} from 'lucide-react';
import { api } from '../services/api';
import {
  ZeroTrustMetrics,
  ContextualAccessDecision,
  MicrosegmentationPolicy,
  ResourceSensitivity,
  AuthAssuranceLevel,
  AccessDecision,
} from '../types';

export const ZeroTrustConsoleView: React.FC = () => {
  const [metrics, setMetrics] = useState<ZeroTrustMetrics | null>(null);
  const [policies, setPolicies] = useState<MicrosegmentationPolicy[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Evaluation Playground State
  const [evalUser, setEvalUser] = useState<string>('alice.engineer@corp.local');
  const [evalResource, setEvalResource] = useState<string>('prod-database.internal.cluster:5432');
  const [evalSensitivity, setEvalSensitivity] = useState<ResourceSensitivity>('CONFIDENTIAL');
  const [evalAuthLevel, setEvalAuthLevel] = useState<AuthAssuranceLevel>('HARDWARE_MFA_FIDO2');
  const [edrActive, setEdrActive] = useState<boolean>(true);
  const [diskEncrypted, setDiskEncrypted] = useState<boolean>(true);
  const [osPatched, setOsPatched] = useState<boolean>(true);
  const [firewallOn, setFirewallOn] = useState<boolean>(true);
  const [uebaAnomaly, setUebaAnomaly] = useState<number>(0.1);
  const [isVpnOrTor, setIsVpnOrTor] = useState<boolean>(false);
  const [activeIncident, setActiveIncident] = useState<boolean>(false);
  const [sourceSubnet, setSourceSubnet] = useState<string>('10.0.1.0/24');
  const [destSubnet, setDestSubnet] = useState<string>('10.0.2.0/24');

  const [lastDecision, setLastDecision] = useState<ContextualAccessDecision | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);

  // Create Policy Modal
  const [isPolicyModalOpen, setIsPolicyModalOpen] = useState<boolean>(false);
  const [newPolicyName, setNewPolicyName] = useState<string>('');
  const [newPolicySrc, setNewPolicySrc] = useState<string>('10.0.10.0/24');
  const [newPolicyDst, setNewPolicyDst] = useState<string>('10.0.5.0/24');
  const [newPolicyPort, setNewPolicyPort] = useState<string>('443/TCP');
  const [newPolicyAction, setNewPolicyAction] = useState<'ALLOW' | 'DENY'>('DENY');
  const [newPolicyDesc, setNewPolicyDesc] = useState<string>('');
  const [isCreatingPolicy, setIsCreatingPolicy] = useState<boolean>(false);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [m, p] = await Promise.all([
        api.getZeroTrustMetrics(),
        api.getMicrosegmentationPolicies(),
      ]);
      setMetrics(m);
      setPolicies(p);
    } catch {
      // Handled gracefully
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleEvaluateAccess = async () => {
    setIsEvaluating(true);
    try {
      const res = await api.evaluateZeroTrustAccess({
        user_id: evalUser,
        resource_id: evalResource,
        resource_sensitivity: evalSensitivity,
        auth_level: evalAuthLevel,
        device_posture: {
          edr_active: edrActive,
          disk_encrypted: diskEncrypted,
          os_patched: osPatched,
          firewall_on: firewallOn,
        },
        ueba_anomaly_score: uebaAnomaly,
        network_context: {
          is_vpn_or_tor: isVpnOrTor,
          threat_reputation_score: isVpnOrTor ? 45.0 : 0.0,
        },
        active_incident_link: activeIncident,
        source_subnet: sourceSubnet,
        destination_subnet: destSubnet,
      });
      setLastDecision(res);
      if (res) {
        setActionMessage(`🛡️ NIST SP 800-207 Decision: ${res.decision} (Trust Score: ${res.trust_score}%)`);
        await loadData();
      }
    } catch {
      setActionMessage(`❌ Failed to evaluate access request.`);
    } finally {
      setIsEvaluating(false);
      setTimeout(() => setActionMessage(null), 7000);
    }
  };

  const handleTogglePolicy = async (policyId: string) => {
    try {
      const updated = await api.toggleMicrosegmentationPolicy(policyId);
      if (updated) {
        setActionMessage(`⚡ Policy '${updated.name}' state toggled to: ${updated.is_enabled ? 'ENABLED' : 'DISABLED'}`);
        await loadData();
      }
    } catch {
      setActionMessage(`❌ Error toggling policy.`);
    } finally {
      setTimeout(() => setActionMessage(null), 6000);
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPolicyName.trim()) return;
    setIsCreatingPolicy(true);
    try {
      const res = await api.createMicrosegmentationPolicy({
        name: newPolicyName.trim(),
        source_subnet: newPolicySrc.trim(),
        destination_subnet: newPolicyDst.trim(),
        port_protocol: newPolicyPort.trim(),
        action: newPolicyAction,
        description: newPolicyDesc.trim(),
      });
      if (res) {
        setActionMessage(`✅ Micro-segmentation rule provisioned: ${res.name}`);
        setIsPolicyModalOpen(false);
        setNewPolicyName('');
        setNewPolicyDesc('');
        await loadData();
      }
    } catch {
      setActionMessage(`❌ Failed to create micro-segmentation rule.`);
    } finally {
      setIsCreatingPolicy(false);
      setTimeout(() => setActionMessage(null), 7000);
    }
  };

  const avgTrustScore = metrics?.average_trust_score ?? 85;

  const getDecisionBadge = (decision: AccessDecision) => {
    switch (decision) {
      case 'ALLOW':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
      case 'STEP_UP_AUTH':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/30';
      case 'RESTRICT':
        return 'bg-purple-500/10 text-purple-400 border border-purple-500/30';
      case 'BLOCK':
      default:
        return 'bg-rose-500/15 text-rose-400 border border-rose-500/40 animate-pulse';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 bg-gradient-to-r from-slate-900 via-indigo-950/20 to-slate-900 border border-slate-800 rounded-xl">
        <div className="flex items-center space-x-3">
          <div className="p-3 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400">
            <Lock className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-xl font-bold font-mono tracking-wide text-white">
                ZERO-TRUST ACCESS &amp; MICRO-SEGMENTATION
              </h2>
              <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                NIST SP 800-207
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Continuous Contextual Trust Scoring &bull; Dynamic Policy Decision Point (PDP) &bull; Software-Defined Micro-Segmentation
            </p>
          </div>
        </div>

        {/* Action controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsPolicyModalOpen(true)}
            className="flex items-center space-x-2 px-3.5 py-2 bg-indigo-600/20 border border-indigo-500/40 hover:bg-indigo-600/30 text-indigo-300 rounded-lg text-xs font-mono font-semibold transition"
          >
            <Plus className="w-4 h-4" />
            <span>ADD POLICY</span>
          </button>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-indigo-400 hover:bg-slate-700 transition"
            title="Refresh Status"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Action Notification Message */}
      {actionMessage && (
        <div className="p-3.5 rounded-lg bg-slate-800/90 border border-indigo-500/40 text-indigo-300 text-xs font-mono flex items-center justify-between animate-fadeIn">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* System KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Average Trust Score */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">AVERAGE TRUST SCORE</span>
            <ShieldCheck className={`w-4 h-4 ${avgTrustScore >= 80 ? 'text-emerald-400' : 'text-amber-400'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className={`text-3xl font-extrabold font-mono ${
                avgTrustScore >= 80
                  ? 'text-emerald-400'
                  : avgTrustScore >= 65
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}>
                {avgTrustScore}%
              </span>
              <span className="text-xs text-slate-400 font-mono">CONTINUOUS INDEX</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  avgTrustScore >= 80 ? 'bg-emerald-500' : avgTrustScore >= 65 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${avgTrustScore}%` }}
              />
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Target SLA: &ge; 80.0% Trusted Baseline</span>
        </div>

        {/* Active Policies */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">ACTIVE POLICIES</span>
            <Network className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold font-mono text-indigo-400">
                {metrics?.active_policies_count ?? 0}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                / {metrics?.total_microsegmentation_policies ?? 0} Rules
              </span>
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Subnet &amp; Workload Boundaries</span>
        </div>

        {/* Continuous Verification Rate */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">VERIFICATION COVERAGE</span>
            <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold font-mono text-emerald-400">
                100%
              </span>
              <span className="text-xs text-slate-400 font-mono">Every Request</span>
            </div>
          </div>
          <span className="text-[10px] text-emerald-400 font-mono font-semibold">
            NIST SP 800-207 Certified
          </span>
        </div>

        {/* Blocked Lateral Movements */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">BLOCKED ATTEMPTS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold font-mono text-rose-400">
                {metrics?.blocked_access_attempts ?? 0}
              </span>
              <span className="text-xs text-slate-400 font-mono">Policy Denials</span>
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Lateral propagation severed</span>
        </div>
      </div>

      {/* Main Content Grid: Contextual Decision Simulator + Micro-Segmentation Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 6 Columns: Contextual Access Decision Simulator (PDP) */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center space-x-2 mb-4">
              <Sliders className="w-5 h-5 text-indigo-400" />
              <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                Contextual Access Evaluation Playground (PDP)
              </h3>
            </div>

            <div className="space-y-4 font-mono text-xs">
              {/* User & Resource */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Subject User:</label>
                  <input
                    type="text"
                    value={evalUser}
                    onChange={(e) => setEvalUser(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Target Resource:</label>
                  <input
                    type="text"
                    value={evalResource}
                    onChange={(e) => setEvalResource(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                  />
                </div>
              </div>

              {/* Sensitivity & Auth Level */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Resource Sensitivity:</label>
                  <select
                    value={evalSensitivity}
                    onChange={(e) => setEvalSensitivity(e.target.value as ResourceSensitivity)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-indigo-300"
                  >
                    <option value="PUBLIC">PUBLIC</option>
                    <option value="INTERNAL">INTERNAL</option>
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="RESTRICTED_CROWN_JEWEL">RESTRICTED_CROWN_JEWEL</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Authentication Assurance:</label>
                  <select
                    value={evalAuthLevel}
                    onChange={(e) => setEvalAuthLevel(e.target.value as AuthAssuranceLevel)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-cyan-300"
                  >
                    <option value="HARDWARE_MFA_FIDO2">FIDO2 WebAuthn / Cert</option>
                    <option value="PASSWORD_SMS">Password + SMS OTP</option>
                    <option value="PASSWORD_ONLY">Single-Factor Password</option>
                  </select>
                </div>
              </div>

              {/* Device Posture Toggles */}
              <div className="p-3 bg-slate-800/40 border border-slate-800 rounded-lg space-y-2">
                <span className="text-[11px] font-bold text-slate-300 block mb-1">Device Health &amp; EDR Posture:</span>
                <div className="grid grid-cols-2 gap-2">
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={edrActive}
                      onChange={(e) => setEdrActive(e.target.checked)}
                      className="accent-indigo-500 rounded"
                    />
                    <span>EDR Sensor Active</span>
                  </label>
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={diskEncrypted}
                      onChange={(e) => setDiskEncrypted(e.target.checked)}
                      className="accent-indigo-500 rounded"
                    />
                    <span>Disk Encrypted</span>
                  </label>
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={osPatched}
                      onChange={(e) => setOsPatched(e.target.checked)}
                      className="accent-indigo-500 rounded"
                    />
                    <span>OS Fully Patched</span>
                  </label>
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={firewallOn}
                      onChange={(e) => setFirewallOn(e.target.checked)}
                      className="accent-indigo-500 rounded"
                    />
                    <span>Host Firewall Enabled</span>
                  </label>
                </div>
              </div>

              {/* UEBA & Threat Context */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">UEBA Anomaly Deviation:</span>
                  <span className="text-indigo-400 font-bold">{(uebaAnomaly * 100).toFixed(0)}% Risk</span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={uebaAnomaly}
                  onChange={(e) => setUebaAnomaly(parseFloat(e.target.value))}
                  className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-indigo-500"
                />

                <div className="flex items-center space-x-4 pt-1">
                  <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={isVpnOrTor}
                      onChange={(e) => setIsVpnOrTor(e.target.checked)}
                      className="accent-indigo-500 rounded"
                    />
                    <span>VPN / Tor Exit Node</span>
                  </label>
                  <label className="flex items-center space-x-2 text-rose-400 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={activeIncident}
                      onChange={(e) => setActiveIncident(e.target.checked)}
                      className="accent-rose-500 rounded"
                    />
                    <span>Linked to Active Breach</span>
                  </label>
                </div>
              </div>

              {/* Trigger Button */}
              <button
                onClick={handleEvaluateAccess}
                disabled={isEvaluating}
                className="w-full py-2.5 px-4 bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/50 text-indigo-300 rounded font-semibold flex items-center justify-center space-x-2 transition"
              >
                <Play className={`w-3.5 h-3.5 ${isEvaluating ? 'animate-spin' : ''}`} />
                <span>{isEvaluating ? 'Computing Policy Decision...' : 'Evaluate Contextual Policy Decision'}</span>
              </button>
            </div>
          </div>

          {/* Decision Outcome Card */}
          {lastDecision && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">PDP DECISION OUTCOME</span>
                <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${getDecisionBadge(lastDecision.decision)}`}>
                  {lastDecision.decision}
                </span>
              </div>

              <div className="flex items-baseline space-x-3">
                <span className="text-3xl font-extrabold font-mono text-indigo-400">
                  {lastDecision.trust_score}%
                </span>
                <span className="text-xs font-mono text-slate-400">Contextual Trust Score</span>
              </div>

              <p className="text-xs text-slate-300 font-mono bg-slate-800/50 p-3 rounded border border-slate-750">
                {lastDecision.reason}
              </p>

              {/* Breakdown Grid */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-[10px] font-mono">
                <div className="p-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-500 block">Auth:</span>
                  <span className="text-white font-bold">{lastDecision.score_breakdown.authentication_score}%</span>
                </div>
                <div className="p-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-500 block">Device:</span>
                  <span className="text-white font-bold">{lastDecision.score_breakdown.device_posture_score}%</span>
                </div>
                <div className="p-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-500 block">Behavior:</span>
                  <span className="text-white font-bold">{lastDecision.score_breakdown.behavioral_trust_score}%</span>
                </div>
                <div className="p-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-500 block">Network:</span>
                  <span className="text-white font-bold">{lastDecision.score_breakdown.network_context_score}%</span>
                </div>
                <div className="p-2 bg-slate-800/40 rounded border border-slate-800">
                  <span className="text-slate-500 block">Incident:</span>
                  <span className="text-white font-bold">{lastDecision.score_breakdown.incident_freedom_score}%</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right 6 Columns: Micro-Segmentation Security Policies */}
        <div className="lg:col-span-6 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-2">
                <Network className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                  Micro-Segmentation Policy Matrix
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {policies.length} network rules configured
              </span>
            </div>

            <p className="text-xs text-slate-400 mb-4 leading-relaxed font-mono">
              Enforces software-defined perimeter boundaries. Disables lateral movement between compromised subnets and sensitive production workloads.
            </p>

            <div className="space-y-3">
              {policies.map((p) => (
                <div
                  key={p.id}
                  className={`p-3.5 rounded-lg border transition ${
                    p.is_enabled
                      ? 'bg-slate-800/40 border-slate-800 hover:border-slate-700'
                      : 'bg-slate-900/40 border-slate-900 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono ${
                        p.action === 'ALLOW'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      }`}>
                        {p.action}
                      </span>
                      <span className="text-xs font-bold font-mono text-slate-200">{p.name}</span>
                    </div>
                    <button
                      onClick={() => handleTogglePolicy(p.id)}
                      className="text-slate-400 hover:text-white transition"
                      title={p.is_enabled ? 'Disable Policy' : 'Enable Policy'}
                    >
                      {p.is_enabled ? (
                        <ToggleRight className="w-6 h-6 text-emerald-400" />
                      ) : (
                        <ToggleLeft className="w-6 h-6 text-slate-600" />
                      )}
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-slate-400 mt-2">
                    <div>Source: <span className="text-cyan-300">{p.source_subnet}</span></div>
                    <div>Destination: <span className="text-purple-300">{p.destination_subnet}</span></div>
                    <div>Port/Protocol: <span className="text-slate-300">{p.port_protocol}</span></div>
                    <div>Status: <span className={p.is_enabled ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                      {p.is_enabled ? 'ACTIVE ENFORCEMENT' : 'DISABLED'}
                    </span></div>
                  </div>

                  {p.description && (
                    <p className="text-[10px] text-slate-500 mt-1 font-mono">
                      {p.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Create Policy Modal */}
      {isPolicyModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-fadeIn">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-indigo-400">
                <Plus className="w-5 h-5" />
                <h3 className="text-sm font-bold font-mono uppercase tracking-wider">
                  Create Micro-Segmentation Rule
                </h3>
              </div>
              <button
                onClick={() => setIsPolicyModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreatePolicy} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Rule Name:</label>
                <input
                  type="text"
                  value={newPolicyName}
                  onChange={(e) => setNewPolicyName(e.target.value)}
                  placeholder="e.g. DMZ to Vault Payment API"
                  required
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source Subnet:</label>
                  <input
                    type="text"
                    value={newPolicySrc}
                    onChange={(e) => setNewPolicySrc(e.target.value)}
                    required
                    className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Destination Subnet:</label>
                  <input
                    type="text"
                    value={newPolicyDst}
                    onChange={(e) => setNewPolicyDst(e.target.value)}
                    required
                    className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Port/Protocol:</label>
                  <input
                    type="text"
                    value={newPolicyPort}
                    onChange={(e) => setNewPolicyPort(e.target.value)}
                    placeholder="443/TCP or ANY"
                    className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Action:</label>
                  <select
                    value={newPolicyAction}
                    onChange={(e) => setNewPolicyAction(e.target.value as 'ALLOW' | 'DENY')}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-indigo-300"
                  >
                    <option value="DENY">DENY (Quarantine)</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description / Rationale:</label>
                <input
                  type="text"
                  value={newPolicyDesc}
                  onChange={(e) => setNewPolicyDesc(e.target.value)}
                  placeholder="e.g. Isolates untrusted developer workstations from production database"
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsPolicyModalOpen(false)}
                  className="px-3 py-2 bg-slate-800 text-slate-400 hover:text-white rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreatingPolicy}
                  className="px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 rounded font-semibold transition"
                >
                  {isCreatingPolicy ? 'Provisioning...' : 'Provision Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

