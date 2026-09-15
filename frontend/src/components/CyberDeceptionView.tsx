import React, { useState, useEffect } from 'react';
import {
  Eye,
  ShieldCheck,
  Zap,
  RefreshCw,
  Plus,
  Terminal,
  Server,
  Key,
  Database,
  FileText,
  AlertTriangle,
  Play,
  CheckCircle2,
  Lock,
  Radio,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '../services/api';
import {
  Honeytoken,
  DecoyService,
  DeceptionMetrics,
  HoneytokenType,
  HoneytokenTripwireResponse,
} from '../types';

export const CyberDeceptionView: React.FC = () => {
  const [metrics, setMetrics] = useState<DeceptionMetrics | null>(null);
  const [honeytokens, setHoneytokens] = useState<Honeytoken[]>([]);
  const [decoys, setDecoys] = useState<DecoyService[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Deploy Token Modal / Form
  const [isDeployOpen, setIsDeployOpen] = useState<boolean>(false);
  const [deployType, setDeployType] = useState<HoneytokenType>('AWS_SECRET_KEY');
  const [deployName, setDeployName] = useState<string>('');
  const [deployPath, setDeployPath] = useState<string>('');
  const [isDeploying, setIsDeploying] = useState<boolean>(false);

  // Decoy probe simulation state
  const [selectedDecoyId, setSelectedDecoyId] = useState<string>('decoy_ssh_01');
  const [probeCommand, setProbeCommand] = useState<string>('whoami');
  const [isProbing, setIsProbing] = useState<boolean>(false);
  const [lastProbeOutput, setLastProbeOutput] = useState<string | null>(null);

  // Tripwire response modal / display
  const [lastTripwireAlert, setLastTripwireAlert] = useState<HoneytokenTripwireResponse | null>(null);
  const [copiedTokenId, setCopiedTokenId] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [m, tokens, d] = await Promise.all([
        api.getDeceptionMetrics(),
        api.getHoneytokens(),
        api.getDecoyServices(),
      ]);
      setMetrics(m);
      setHoneytokens(tokens);
      setDecoys(d);
    } catch {
      // Gracefully handled
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleDeployToken = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deployName.trim()) return;
    setIsDeploying(true);
    try {
      const res = await api.deployHoneytoken(
        deployType,
        deployName.trim(),
        deployPath.trim() || undefined
      );
      if (res) {
        setActionMessage(`🎯 Honeytoken deployed successfully: ${res.name} at ${res.bait_path}`);
        setIsDeployOpen(false);
        setDeployName('');
        setDeployPath('');
        await loadData();
      }
    } catch {
      setActionMessage(`❌ Failed to deploy honeytoken.`);
    } finally {
      setIsDeploying(false);
      setTimeout(() => setActionMessage(null), 7000);
    }
  };

  const handleSimulateTripwire = async (token: Honeytoken) => {
    setIsLoading(true);
    try {
      const res = await api.triggerHoneytokenTripwire(token.id);
      setLastTripwireAlert(res);
      if (res?.tripwire_triggered) {
        setActionMessage(`🚨 TRIPWIRE BREACH DETECTED: 100% True-Positive Alert generated for ${token.name}!`);
        await loadData();
      }
    } catch {
      setActionMessage(`❌ Error triggering honeytoken tripwire.`);
    } finally {
      setIsLoading(false);
      setTimeout(() => setActionMessage(null), 8000);
    }
  };

  const handleProbeDecoy = async () => {
    if (!probeCommand.trim()) return;
    setIsProbing(true);
    try {
      const res = await api.interactWithDecoy(selectedDecoyId, probeCommand.trim());
      if (res?.interaction_entry) {
        setLastProbeOutput(res.interaction_entry.simulated_output);
        setActionMessage(`🛰️ Decoy Honeynet captured adversary payload: "${probeCommand}"`);
        await loadData();
      }
    } catch {
      setActionMessage(`❌ Decoy probe failed.`);
    } finally {
      setIsProbing(false);
      setTimeout(() => setActionMessage(null), 6000);
    }
  };

  const handleCopyBait = (token: Honeytoken) => {
    navigator.clipboard.writeText(token.token_value || token.masked_value);
    setCopiedTokenId(token.id);
    setTimeout(() => setCopiedTokenId(null), 2000);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'API_KEY':
      case 'JWT_TOKEN':
        return <Key className="w-3.5 h-3.5 text-amber-400" />;
      case 'DATABASE_CREDENTIAL':
        return <Database className="w-3.5 h-3.5 text-cyan-400" />;
      case 'CANARY_FILE':
        return <FileText className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <Lock className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-5 bg-gradient-to-r from-slate-900 via-amber-950/20 to-slate-900 border border-slate-800 rounded-xl">
        <div className="flex items-center space-x-3">
          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400">
            <Eye className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-xl font-bold font-mono tracking-wide text-white">
                CYBER DECEPTION &amp; DECOY HONEYNET
              </h2>
              <span className="px-2 py-0.5 text-xs font-mono font-bold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                100% FIDELITY &bull; ZERO FALSE POSITIVES
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Canary Honeytokens &bull; High-Interaction Faux Micro-Services &bull; Automated SOAR Containment Tripwires
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsDeployOpen(true)}
            className="flex items-center space-x-2 px-3.5 py-2 bg-amber-500/20 border border-amber-500/40 hover:bg-amber-500/30 text-amber-300 rounded-lg text-xs font-mono font-semibold transition"
          >
            <Plus className="w-4 h-4" />
            <span>DEPLOY HONEYTOKEN</span>
          </button>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-amber-400 hover:bg-slate-700 transition"
            title="Refresh Deception Status"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Action Notification Message */}
      {actionMessage && (
        <div className="p-3.5 rounded-lg bg-slate-800/90 border border-amber-500/40 text-amber-300 text-xs font-mono flex items-center justify-between animate-fadeIn">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Active Honeytokens */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">ACTIVE HONEYTOKENS</span>
            <Key className="w-4 h-4 text-amber-400" />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold font-mono text-amber-400">
                {metrics?.active_honeytokens ?? 0}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                / {metrics?.total_honeytokens_deployed ?? 0} Deployed
              </span>
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Planted across configs &amp; environment files
          </span>
        </div>

        {/* Tripwires Triggered */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">TRIPWIRES HIT</span>
            <AlertTriangle className={`w-4 h-4 ${(metrics?.tripped_honeytokens ?? 0) > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-500'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className={`text-3xl font-extrabold font-mono ${(metrics?.tripped_honeytokens ?? 0) > 0 ? 'text-rose-400' : 'text-slate-200'}`}>
                {metrics?.tripped_honeytokens ?? 0}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ({metrics?.total_honeytoken_hits ?? 0} Total Hits)
              </span>
            </div>
          </div>
          <span className="text-[10px] text-emerald-400 font-mono font-semibold">
            100% True-Positive Breach Guarantee
          </span>
        </div>

        {/* Decoy Honeynet Services */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">DECOY SERVICES</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold font-mono text-cyan-400">
                {metrics?.total_decoys_online ?? 0}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Micro-Honeypots Online
              </span>
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            SSH (2222), Redis (6380), Admin (8443), SQL (5433)
          </span>
        </div>

        {/* Captured Adversary Telemetry */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">CAPTURED PROBES</span>
            <Terminal className="w-4 h-4 text-purple-400" />
          </div>
          <div className="my-2">
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl font-extrabold font-mono text-purple-400">
                {metrics?.total_decoy_interactions ?? 0}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Adversary Interactions
              </span>
            </div>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Full command &amp; query payload capture
          </span>
        </div>
      </div>

      {/* Main Grid: Honeytoken Inventory + Decoy Honeynet */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 Columns: Honeytoken Bait Inventory */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-2">
                <Key className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                  Canary Honeytoken Inventory
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {honeytokens.length} baits active
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="pb-2">TYPE &amp; NAME</th>
                    <th className="pb-2">BAIT LOCATION</th>
                    <th className="pb-2">VALUE</th>
                    <th className="pb-2">STATUS</th>
                    <th className="pb-2 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {honeytokens.map((token) => (
                    <tr key={token.id} className="hover:bg-slate-800/20">
                      <td className="py-3">
                        <div className="flex items-center space-x-2">
                          {getTypeIcon(token.token_type)}
                          <div>
                            <div className="font-semibold text-slate-200">{token.name}</div>
                            <span className="text-[10px] text-slate-500 font-mono">{token.token_type}</span>
                          </div>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-cyan-300 font-mono">
                          {token.bait_path}
                        </span>
                      </td>
                      <td className="py-3">
                        <div className="flex items-center space-x-1">
                          <span className="text-slate-400 text-[10px] font-mono">{token.masked_value}</span>
                          <button
                            onClick={() => handleCopyBait(token)}
                            className="p-1 text-slate-500 hover:text-amber-400 transition"
                            title="Copy Bait String"
                          >
                            {copiedTokenId === token.id ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          token.status === 'TRIPPED'
                            ? 'bg-rose-500/15 text-rose-400 border border-rose-500/40 animate-pulse'
                            : token.status === 'ACTIVE'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {token.status}
                          {token.hit_count > 0 && ` (${token.hit_count})`}
                        </span>
                      </td>
                      <td className="py-3 text-right">
                        <button
                          onClick={() => handleSimulateTripwire(token)}
                          disabled={isLoading}
                          className="px-2.5 py-1 bg-rose-600/20 hover:bg-rose-600/30 border border-rose-500/40 text-rose-300 rounded text-[10px] font-mono transition"
                          title="Simulate an adversary accessing this honeytoken"
                        >
                          Simulate Access
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Live Tripwire Breach Feedback */}
          {lastTripwireAlert && lastTripwireAlert.tripwire_triggered && lastTripwireAlert.alert && (
            <div className="bg-rose-950/20 border border-rose-500/50 rounded-xl p-5 animate-fadeIn">
              <div className="flex items-center space-x-2 text-rose-400 mb-3">
                <AlertTriangle className="w-5 h-5 animate-pulse" />
                <h4 className="text-sm font-bold font-mono uppercase tracking-wider">
                  Live Tripwire Breach Triggered (Zero False Positive)
                </h4>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3 text-xs font-mono">
                <div className="p-2.5 bg-slate-900/80 rounded border border-rose-900/50">
                  <span className="text-[10px] text-slate-400">TOKEN COMPROMISED:</span>
                  <div className="font-bold text-white mt-0.5">{lastTripwireAlert.alert.token_name}</div>
                </div>
                <div className="p-2.5 bg-slate-900/80 rounded border border-rose-900/50">
                  <span className="text-[10px] text-slate-400">ATTACKER IP:</span>
                  <div className="font-bold text-rose-400 mt-0.5">{lastTripwireAlert.alert.source_ip}</div>
                </div>
                <div className="p-2.5 bg-slate-900/80 rounded border border-rose-900/50">
                  <span className="text-[10px] text-slate-400">MITRE ATT&amp;CK:</span>
                  <div className="font-bold text-amber-400 mt-0.5">
                    {lastTripwireAlert.alert.mitre_technique_id}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-900/80 rounded border border-rose-900/50">
                  <span className="text-[10px] text-slate-400">AUTONOMOUS SOAR:</span>
                  <div className="font-bold text-emerald-400 mt-0.5">
                    {lastTripwireAlert.alert.recommended_soar_playbook}
                  </div>
                </div>
              </div>

              <div className="text-xs font-mono text-slate-300">
                Action Executed: {lastTripwireAlert.alert.recommended_action}
              </div>
            </div>
          )}
        </div>

        {/* Right 5 Columns: Decoy Honeynet Services & Interactive Probe */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center space-x-2 mb-4">
              <Server className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                Decoy Honeynet Services
              </h3>
            </div>

            <p className="text-xs text-slate-400 mb-4 leading-relaxed">
              Lightweight micro-emulations of enticing enterprise ports and protocols. They record attacker commands into forensic threat intelligence.
            </p>

            {/* Decoy Cards */}
            <div className="space-y-3 mb-5">
              {decoys.map((d) => (
                <div
                  key={d.id}
                  onClick={() => setSelectedDecoyId(d.id)}
                  className={`p-3 rounded-lg border cursor-pointer transition ${
                    selectedDecoyId === d.id
                      ? 'bg-slate-800/80 border-cyan-500/60 shadow-sm shadow-cyan-500/10'
                      : 'bg-slate-800/30 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-slate-200">{d.name}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono">
                      PORT {d.port} &bull; {d.status}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1">
                    Banner: {d.fake_banner}
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mt-2">
                    <span>Protocol: {d.protocol}</span>
                    <span className="text-cyan-400 font-bold">{d.interaction_count} probes captured</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Interactive Probe Simulator */}
            <div className="p-3.5 bg-slate-800/40 border border-slate-800 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-300">Simulate Attacker Probe:</span>
                <span className="text-[10px] font-mono text-cyan-400">Target: {selectedDecoyId}</span>
              </div>

              <div className="flex space-x-2">
                <input
                  type="text"
                  value={probeCommand}
                  onChange={(e) => setProbeCommand(e.target.value)}
                  placeholder="e.g. whoami, uname -a, KEYS *, SHOW TABLES"
                  className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleProbeDecoy}
                  disabled={isProbing}
                  className="px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/50 text-cyan-300 rounded text-xs font-mono flex items-center space-x-1 transition"
                >
                  <Play className={`w-3 h-3 ${isProbing ? 'animate-spin' : ''}`} />
                  <span>Send</span>
                </button>
              </div>

              {lastProbeOutput && (
                <div className="p-2.5 bg-black/70 border border-slate-800 rounded font-mono text-[11px] text-emerald-400 whitespace-pre-wrap">
                  {lastProbeOutput}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Deploy Honeytoken Modal */}
      {isDeployOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-fadeIn">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-amber-400">
                <Plus className="w-5 h-5" />
                <h3 className="text-sm font-bold font-mono uppercase tracking-wider">
                  Deploy Enterprise Honeytoken
                </h3>
              </div>
              <button
                onClick={() => setIsDeployOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleDeployToken} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Honeytoken Type:</label>
                <select
                  value={deployType}
                  onChange={(e) => setDeployType(e.target.value as HoneytokenType)}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                >
                  <option value="AWS_SECRET_KEY">AWS Secret Key (.env.staging)</option>
                  <option value="DATABASE_CREDENTIAL">Database Credential (database.yaml)</option>
                  <option value="API_KEY">API Key (payment_gateway.json)</option>
                  <option value="JWT_TOKEN">Admin JWT Token (admin_session.jwt)</option>
                  <option value="CANARY_FILE">Canary File (confidential_payroll.xlsx)</option>
                  <option value="SSH_KEY">SSH Key (.ssh/id_rsa_backup)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Decoy Name / Label:</label>
                <input
                  type="text"
                  value={deployName}
                  onChange={(e) => setDeployName(e.target.value)}
                  placeholder="e.g. Master Vault Encryption Key"
                  required
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Bait Path (Optional):</label>
                <input
                  type="text"
                  value={deployPath}
                  onChange={(e) => setDeployPath(e.target.value)}
                  placeholder="Default recommended path will be assigned if left empty"
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-slate-200"
                />
              </div>

              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded text-[11px] text-amber-300">
                Any unauthorized access to this canary credential will instantly generate a Critical alert and initiate SOAR host isolation.
              </div>

              <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsDeployOpen(false)}
                  className="px-3 py-2 bg-slate-800 text-slate-400 hover:text-white rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isDeploying}
                  className="px-4 py-2 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 rounded font-semibold transition"
                >
                  {isDeploying ? 'Deploying...' : 'Deploy Honeytoken'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

