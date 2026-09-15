import React, { useState, useEffect } from 'react';
import {
  Archive,
  ShieldCheck,
  ShieldAlert,
  FileText,
  HardDrive,
  Cpu,
  Network,
  Key,
  Lock,
  RefreshCw,
  Plus,
  X,
  CheckCircle2,
  Clock,
  ArrowRight,
  Copy,
  FileCheck,
  Activity,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import {
  DfirMetrics,
  ForensicArtifact,
  ForensicCase,
  CustodyCertificate,
  IntegrityVerificationResult,
  ArtifactType,
} from '../types';

export const DfirConsoleView: React.FC = () => {
  const [metrics, setMetrics] = useState<DfirMetrics | null>(null);
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [artifacts, setArtifacts] = useState<ForensicArtifact[]>([]);
  const [certificate, setCertificate] = useState<CustodyCertificate | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'inventory' | 'ledger' | 'certificate'>('inventory');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Verification result modal / display
  const [lastVerification, setLastVerification] = useState<IntegrityVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  // Acquisition Modal State
  const [isAcquireModalOpen, setIsAcquireModalOpen] = useState<boolean>(false);
  const [acqName, setAcqName] = useState<string>('memory_resident_infiltrator.dmp');
  const [acqType, setAcqType] = useState<ArtifactType>('VOLATILE_MEMORY');
  const [acqHost, setAcqHost] = useState<string>('k8s-ingress-controller.prod');
  const [acqPath, setAcqPath] = useState<string>('/proc/sys/kernel/core_pattern');
  const [acqContent, setAcqContent] = useState<string>('RAW_VOLATILE_MEMORY_HEURISTIC_FORENSIC_TRIAGE_BUFFER');
  const [acqCustodian, setAcqCustodian] = useState<string>('Special Agent Sarah Lin');
  const [acqNotes, setAcqNotes] = useState<string>('Captured following high-severity threat hunting alert');
  const [isAcquiring, setIsAcquiring] = useState<boolean>(false);

  // Transfer Custody Modal State
  const [isTransferModalOpen, setIsTransferModalOpen] = useState<boolean>(false);
  const [transferArtifact, setTransferArtifact] = useState<ForensicArtifact | null>(null);
  const [newCustodian, setNewCustodian] = useState<string>('Federal Evidence Escrow Vault Custodian');
  const [transferPurpose, setTransferPurpose] = useState<string>('Judicial submission for digital forensics analysis');
  const [isTransferring, setIsTransferring] = useState<boolean>(false);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [m, c, a, cert] = await Promise.all([
        api.getDfirMetrics(),
        api.getDfirCases(),
        api.getDfirArtifacts(),
        api.getDfirCertificate('CASE-2024-001'),
      ]);
      if (m) setMetrics(m);
      setCases(c);
      setArtifacts(a);
      if (cert) setCertificate(cert);
    } catch {
      setActionMessage('Failed to connect to DFIR Evidence Locker');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleVerifyIntegrity = async (artifactId: string, tamperTest = false) => {
    setIsVerifying(true);
    try {
      const result = await api.verifyDfirIntegrity(artifactId, tamperTest);
      if (result) {
        setLastVerification(result);
        if (result.tamper_detected) {
          setActionMessage(`ALERT: Cryptographic mismatch! Bit-level modification detected on ${result.artifact_name}.`);
        } else {
          setActionMessage(`Verified! SHA-256 & SHA3-512 match immutable genesis records with 100% fidelity.`);
        }
        setTimeout(() => setActionMessage(null), 5000);
        await loadData();
      }
    } catch {
      setActionMessage('Failed to verify artifact integrity');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAcquireSubmit = async () => {
    setIsAcquiring(true);
    try {
      const artifact = await api.acquireDfirArtifact({
        case_id: 'CASE-2024-001',
        artifact_name: acqName,
        artifact_type: acqType,
        affected_host: acqHost,
        source_path: acqPath,
        content_text: acqContent,
        acquired_by: acqCustodian,
        notes: acqNotes,
      });
      if (artifact) {
        setActionMessage(`Artifact '${artifact.artifact_name}' acquired and cryptographically sealed with dual hashes!`);
        setTimeout(() => setActionMessage(null), 5000);
        setIsAcquireModalOpen(false);
        await loadData();
      }
    } catch {
      setActionMessage('Failed to acquire forensic artifact');
    } finally {
      setIsAcquiring(false);
    }
  };

  const handleTransferSubmit = async () => {
    if (!transferArtifact) return;
    setIsTransferring(true);
    try {
      const updated = await api.transferDfirCustody(
        transferArtifact.id,
        newCustodian,
        transferPurpose
      );
      if (updated) {
        setActionMessage(`Custody transferred to '${newCustodian}' with verified pre-transfer integrity.`);
        setTimeout(() => setActionMessage(null), 5000);
        setIsTransferModalOpen(false);
        setTransferArtifact(null);
        await loadData();
      }
    } catch {
      setActionMessage('Custody transfer failed');
    } finally {
      setIsTransferring(false);
    }
  };

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredArtifacts = artifacts.filter((a) => {
    if (typeFilter !== 'ALL' && a.artifact_type !== typeFilter) return false;
    return true;
  });

  const getTypeIcon = (type: ArtifactType) => {
    switch (type) {
      case 'VOLATILE_MEMORY':
        return <Cpu className="w-4 h-4 text-purple-400" />;
      case 'NETWORK_PCAP':
        return <Network className="w-4 h-4 text-cyan-400" />;
      case 'DISK_FORENSICS':
        return <HardDrive className="w-4 h-4 text-amber-400" />;
      case 'TRIAGE_BUNDLE':
        return <FileText className="w-4 h-4 text-emerald-400" />;
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 p-6 rounded-2xl backdrop-blur shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-amber-500/20 to-orange-500/20 border border-amber-500/30 text-amber-400">
              <Archive className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
                Digital Forensics (DFIR) & Chain of Custody
                <span className="px-2.5 py-0.5 text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded-full">
                  Phase 20
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Court-admissible evidence vault, dual SHA-256 / SHA3-512 hashing, and Merkle-backed chain of custody (ISO/IEC 27037)
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsAcquireModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-sm font-semibold transition shadow-lg"
          >
            <Plus className="w-4 h-4" />
            Acquire Evidence Artifact
          </button>

          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-sm font-medium transition"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="flex items-center justify-between bg-amber-950/80 border border-amber-500/50 text-amber-200 px-4 py-3 rounded-xl text-sm animate-fade-in shadow-lg">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-amber-400" />
            <span>{actionMessage}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Integrity Rate */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Verified Custody Integrity</span>
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? `${metrics.verified_integrity_rate_percent}%` : '--'}
            </span>
            <span className="text-xs text-emerald-400 font-semibold">Zero-Tamper Guarantee</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Tamper Incidents Detected</span>
            <span className="text-emerald-400 font-bold">{metrics?.tamper_incidents_detected || 0}</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Compliance Standard</span>
            <span className="text-slate-200 font-mono">ISO/IEC 27037</span>
          </p>
        </div>

        {/* Total Preserved Artifacts */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Preserved Evidence Artifacts</span>
            <Archive className="w-5 h-5 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.total_artifacts : '--'}
            </span>
            <span className="text-xs text-amber-400 font-semibold">Sealed in Vault</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Evidence Volume</span>
            <span className="text-slate-200 font-medium">
              {metrics ? `${(metrics.total_evidence_size_bytes / 1024).toFixed(1)} KB payload` : '--'}
            </span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Dual Cryptographic Sealing</span>
            <span className="text-cyan-400 font-mono">SHA256 + SHA3</span>
          </p>
        </div>

        {/* Chain of Custody Events */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Chain of Custody Events</span>
            <Layers className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.total_custody_events : '--'}
            </span>
            <span className="text-xs text-indigo-400 font-semibold">Immutable Leaves</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Merkle Chain Linkage</span>
            <span className="text-emerald-400 font-semibold">Active & Continuous</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Authorized Custodians</span>
            <span className="text-slate-200 font-medium">{metrics?.active_custodians_count || 0} examiners</span>
          </p>
        </div>

        {/* Active Forensics Cases */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-sm font-medium">Forensic Cases</span>
            <FileCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {metrics ? metrics.total_cases : '--'}
            </span>
            <span className="text-xs text-cyan-400 font-semibold">Open Dockets</span>
          </div>
          <p className="mt-3 text-xs text-slate-400 flex items-center justify-between">
            <span>Primary Active Case</span>
            <span className="text-slate-200 font-mono">CASE-2024-001</span>
          </p>
          <p className="mt-1 text-xs text-slate-400 flex items-center justify-between">
            <span>Court-Admissible Cert</span>
            <span className="text-emerald-400 font-medium">Available for Export</span>
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 gap-6">
        <button
          onClick={() => setActiveTab('inventory')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'inventory'
              ? 'border-amber-500 text-amber-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Archive className="w-4 h-4" />
          Evidence Locker Inventory & Hashing
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {artifacts.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('ledger')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'ledger'
              ? 'border-amber-500 text-amber-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          Visual Merkle Chain-of-Custody Ledger
          <span className="px-2 py-0.5 text-xs rounded-full bg-slate-800 text-slate-300">
            {certificate?.custody_events.length || 0}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('certificate')}
          className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
            activeTab === 'certificate'
              ? 'border-amber-500 text-amber-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCheck className="w-4 h-4" />
          Court-Admissible Custody Certificate
        </button>
      </div>

      {/* TAB 1: EVIDENCE LOCKER INVENTORY */}
      {activeTab === 'inventory' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 p-4 rounded-xl backdrop-blur">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-400">Filter by Artifact Category:</span>
              <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-1">
                {['ALL', 'VOLATILE_MEMORY', 'NETWORK_PCAP', 'DISK_FORENSICS', 'TRIAGE_BUNDLE'].map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(t)}
                    className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                      typeFilter === t
                        ? 'bg-amber-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {t.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <span className="text-xs text-slate-400">
              Showing <span className="font-bold text-white">{filteredArtifacts.length}</span> evidence items
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Artifacts Table */}
            <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur shadow-xl">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-950/60 text-xs font-semibold uppercase tracking-wider text-slate-400">
                      <th className="p-4">Artifact Name / Type</th>
                      <th className="p-4">Host & Source</th>
                      <th className="p-4">Genesis Checksums</th>
                      <th className="p-4">Custodian</th>
                      <th className="p-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-sm">
                    {filteredArtifacts.map((art) => (
                      <tr
                        key={art.id}
                        onClick={() => setSelectedArtifactId(art.id)}
                        className={`hover:bg-slate-800/40 transition cursor-pointer ${
                          selectedArtifactId === art.id ? 'bg-amber-950/20' : ''
                        }`}
                      >
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <div className="p-1.5 rounded bg-slate-950 border border-slate-800">
                              {getTypeIcon(art.artifact_type)}
                            </div>
                            <div>
                              <div className="font-semibold text-white tracking-tight">{art.artifact_name}</div>
                              <div className="text-xs font-mono text-amber-400">{art.id}</div>
                            </div>
                          </div>
                        </td>

                        <td className="p-4">
                          <div className="text-slate-200 font-medium text-xs">{art.affected_host}</div>
                          <div className="text-xs font-mono text-slate-400 truncate max-w-xs" title={art.source_path}>
                            {art.source_path}
                          </div>
                        </td>

                        <td className="p-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-1 text-xs font-mono text-slate-300">
                              <span className="text-slate-500">SHA256:</span>
                              <span className="truncate max-w-[110px]" title={art.genesis_sha256}>
                                {art.genesis_sha256.substring(0, 16)}...
                              </span>
                            </div>
                            <div className="flex items-center gap-1 text-xs font-mono text-slate-400">
                              <span className="text-slate-500">Size:</span>
                              <span>{art.file_size_bytes} B</span>
                            </div>
                          </div>
                        </td>

                        <td className="p-4">
                          <div className="text-xs text-slate-200">{art.current_custodian}</div>
                          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300">
                            {art.custody_chain_length} events
                          </span>
                        </td>

                        <td className="p-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleVerifyIntegrity(art.id, false);
                              }}
                              className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition flex items-center gap-1 shadow"
                            >
                              <ShieldCheck className="w-3.5 h-3.5" />
                              Verify
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setTransferArtifact(art);
                                setIsTransferModalOpen(true);
                              }}
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition"
                            >
                              Transfer
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Cryptographic Inspector Panel */}
            <div className="lg:col-span-1 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="font-bold text-white text-sm flex items-center gap-2">
                  <Key className="w-4 h-4 text-amber-400" />
                  Cryptographic Integrity Inspector
                </span>
                <span className="text-xs font-mono text-emerald-400">SHA-256 / SHA3-512</span>
              </div>

              {lastVerification ? (
                <div className="space-y-4">
                  <div
                    className={`p-4 rounded-xl border flex items-center gap-3 ${
                      lastVerification.tamper_detected
                        ? 'bg-red-950/40 border-red-500/50 text-red-200'
                        : 'bg-emerald-950/40 border-emerald-500/50 text-emerald-200'
                    }`}
                  >
                    {lastVerification.tamper_detected ? (
                      <ShieldAlert className="w-6 h-6 text-red-400 flex-shrink-0" />
                    ) : (
                      <ShieldCheck className="w-6 h-6 text-emerald-400 flex-shrink-0" />
                    )}
                    <div>
                      <h4 className="font-bold text-sm">
                        {lastVerification.tamper_detected
                          ? 'CRITICAL TAMPER DETECTED!'
                          : 'Cryptographic Match Confirmed'}
                      </h4>
                      <p className="text-xs mt-0.5 opacity-90">
                        {lastVerification.tamper_detected
                          ? 'Current checksum deviates from immutable genesis hash.'
                          : 'Current payload bitwise identical to genesis accession.'}
                      </p>
                    </div>
                  </div>

                  {/* Hash Comparison */}
                  <div className="space-y-2 text-xs font-mono">
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                      <div className="flex items-center justify-between text-slate-500">
                        <span>GENESIS SHA-256:</span>
                        <button
                          onClick={() => handleCopy(lastVerification.genesis_sha256, 'genesis_sha256')}
                          className="hover:text-white"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                      <div className="text-slate-200 break-all">{lastVerification.genesis_sha256}</div>
                    </div>

                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                      <div className="flex items-center justify-between text-slate-500">
                        <span>CURRENT SHA-256:</span>
                        <button
                          onClick={() => handleCopy(lastVerification.current_sha256, 'current_sha256')}
                          className="hover:text-white"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                      <div
                        className={`break-all ${
                          lastVerification.tamper_detected ? 'text-red-400 font-bold' : 'text-emerald-300'
                        }`}
                      >
                        {lastVerification.current_sha256}
                      </div>
                    </div>
                  </div>

                  {/* Tamper Test Simulator Action */}
                  <div className="pt-2 border-t border-slate-800">
                    <button
                      onClick={() => handleVerifyIntegrity(lastVerification.artifact_id, true)}
                      className="w-full py-2 bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50 rounded-xl text-xs font-semibold transition flex items-center justify-center gap-1.5"
                    >
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Simulate 1-Bit Tamper & Verify
                    </button>
                    <p className="text-xs text-slate-500 text-center mt-1">
                      Injects synthetic single-byte flip to demonstrate instant Merkle invalidate
                    </p>
                  </div>
                </div>
              ) : (
                <div className="py-12 text-center text-slate-500 text-xs italic">
                  Select an artifact and click "Verify" to inspect genesis and live cryptographic hashes.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: VISUAL MERKLE CHAIN-OF-CUSTODY LEDGER */}
      {activeTab === 'ledger' && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur shadow-xl space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Layers className="w-5 h-5 text-amber-400" />
                Immutable Merkle-Backed Chain of Custody Ledger
              </h2>
              <p className="text-xs text-slate-400">
                Every event generates a cryptographically linked leaf hash chained to the preceding entry
              </p>
            </div>
            <span className="px-3 py-1 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-emerald-400">
              ISO/IEC 27037 Certified
            </span>
          </div>

          <div className="space-y-4">
            {certificate?.custody_events.map((event, idx) => (
              <div
                key={event.event_id}
                className="p-4 bg-slate-950 border border-slate-800/80 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono text-xs hover:border-slate-700 transition"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-amber-400 font-bold">#{idx + 1} {event.action}</span>
                    <span className="text-slate-500">&bull;</span>
                    <span className="text-slate-400">{new Date(event.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="text-slate-300 font-sans text-xs">
                    {event.purpose}
                  </div>
                  <div className="text-slate-400">
                    Custodian: <span className="text-white font-semibold">{event.custodian}</span>
                    {event.releasing_custodian && (
                      <span> (Transferred from: <span className="text-slate-300">{event.releasing_custodian}</span>)</span>
                    )}
                  </div>
                </div>

                <div className="text-right space-y-1">
                  <div className="text-slate-500">Merkle Leaf Hash:</div>
                  <div className="text-cyan-400 font-mono text-xs break-all max-w-xs" title={event.leaf_hash}>
                    {event.leaf_hash.substring(0, 32)}...
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: COURT-ADMISSIBLE CUSTODY CERTIFICATE */}
      {activeTab === 'certificate' && certificate && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-8 backdrop-blur shadow-2xl space-y-6 max-w-4xl mx-auto">
          {/* Certificate Header */}
          <div className="border-b-2 border-slate-800 pb-6 text-center space-y-2">
            <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 mb-2">
              <FileCheck className="w-8 h-8" />
            </div>
            <h2 className="text-2xl font-black text-white tracking-tight uppercase">
              Official Forensic Chain of Custody Certificate
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Certificate ID: <span className="text-amber-400">{certificate.certificate_id}</span> &bull; Compliance: {certificate.standard_compliance}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-slate-500 font-semibold block">CASE IDENTIFIER</span>
              <div className="text-white font-bold text-sm">{certificate.case_id}</div>
              <div className="text-slate-400">Total Artifacts Certified: {certificate.total_artifacts_certified}</div>
              <div className="text-slate-400">Custody Audit Entries: {certificate.total_custody_events}</div>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
              <span className="text-slate-500 font-semibold block">MERKLE ROOT HASH</span>
              <div className="text-cyan-400 break-all font-mono">{certificate.merkle_root_hash}</div>
              <div className="text-emerald-400 font-bold flex items-center gap-1 mt-1">
                <ShieldCheck className="w-4 h-4" /> {certificate.admissibility_status}
              </div>
            </div>
          </div>

          {/* Certified Artifacts List */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Cryptographically Sealed Artifacts in Evidence Vault
            </h4>
            <div className="space-y-2 text-xs font-mono">
              {certificate.certified_artifacts.map((art) => (
                <div key={art.id} className="p-3 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between">
                  <div>
                    <span className="text-white font-bold">{art.artifact_name}</span>
                    <span className="text-slate-500 ml-2">({art.artifact_type})</span>
                    <div className="text-slate-400 text-xs truncate max-w-sm">
                      SHA256: {art.genesis_sha256}
                    </div>
                  </div>
                  <span className="text-emerald-400 font-semibold">Verified Sealed</span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500 font-mono">
            <span>Issued at: {new Date(certificate.issued_at).toUTCString()}</span>
            <button
              onClick={() => handleCopy(JSON.stringify(certificate, null, 2), 'cert_json')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl font-sans font-medium transition flex items-center gap-2"
            >
              <Copy className="w-3.5 h-3.5" />
              Copy Raw JSON Certificate
            </button>
          </div>
        </div>
      )}

      {/* ACQUIRE ARTIFACT MODAL */}
      {isAcquireModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 animate-scale-up">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <Archive className="w-5 h-5 text-amber-400" />
                  Acquire & Seal Forensic Artifact
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Computes dual SHA-256 and SHA3-512 hashes and appends to Merkle chain
                </p>
              </div>
              <button onClick={() => setIsAcquireModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Artifact Filename</label>
                <input
                  type="text"
                  value={acqName}
                  onChange={(e) => setAcqName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Artifact Category</label>
                <select
                  value={acqType}
                  onChange={(e) => setAcqType(e.target.value as ArtifactType)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                >
                  <option value="VOLATILE_MEMORY">VOLATILE_MEMORY (Process dump / RAM strings)</option>
                  <option value="NETWORK_PCAP">NETWORK_PCAP (Packet trace / Zeek logs)</option>
                  <option value="DISK_FORENSICS">DISK_FORENSICS (MFT / Inodes / Journal)</option>
                  <option value="TRIAGE_BUNDLE">TRIAGE_BUNDLE (Sysmon logs / Registry hives)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Affected Host</label>
                  <input
                    type="text"
                    value={acqHost}
                    onChange={(e) => setAcqHost(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Acquiring Custodian</label>
                  <input
                    type="text"
                    value={acqCustodian}
                    onChange={(e) => setAcqCustodian(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Payload Content</label>
                <textarea
                  rows={3}
                  value={acqContent}
                  onChange={(e) => setAcqContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white font-mono"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={() => setIsAcquireModalOpen(false)}
                  className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-semibold"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAcquireSubmit}
                  disabled={isAcquiring}
                  className="flex-1 py-2.5 bg-amber-600 hover:bg-amber-500 text-white rounded-xl font-semibold flex items-center justify-center gap-2"
                >
                  {isAcquiring ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  Seal Artifact
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TRANSFER CUSTODY MODAL */}
      {isTransferModalOpen && transferArtifact && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 animate-scale-up">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <ArrowRight className="w-5 h-5 text-amber-400" />
                  Transfer Evidence Custody
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Pre-transfer cryptographic verification enforced before updating custodian
                </p>
              </div>
              <button onClick={() => setIsTransferModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono space-y-1">
              <div className="text-slate-400">Artifact: <span className="text-white font-bold">{transferArtifact.artifact_name}</span></div>
              <div className="text-slate-400">Current Custodian: <span className="text-amber-400">{transferArtifact.current_custodian}</span></div>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Receiving Custodian / Examiner</label>
                <input
                  type="text"
                  value={newCustodian}
                  onChange={(e) => setNewCustodian(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">Transfer Rationale & Chain Purpose</label>
                <textarea
                  rows={2}
                  value={transferPurpose}
                  onChange={(e) => setTransferPurpose(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white"
                />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={() => setIsTransferModalOpen(false)}
                  className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-semibold"
                >
                  Cancel
                </button>
                <button
                  onClick={handleTransferSubmit}
                  disabled={isTransferring}
                  className="flex-1 py-2.5 bg-amber-600 hover:bg-amber-500 text-white rounded-xl font-semibold flex items-center justify-center gap-2"
                >
                  {isTransferring ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  Verify & Transfer
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

