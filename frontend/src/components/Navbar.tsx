import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  GitCommit,
  Cpu,
  Workflow,
  Crosshair,
  RefreshCw,
  Radio,
  Layers,
  Flame,
  Eye,
  Lock,
  Target,
  Compass,
  Archive,
  Swords,
  GitFork,
  Cloud,
  Package,
} from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  wsStatus: 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED';
  onRefresh: () => void;
  pendingApprovalsCount: number;
  onOpenReportsModal?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  wsStatus,
  onRefresh,
  pendingApprovalsCount,
  onOpenReportsModal,
}) => {
  const tabs = [
    { id: 'nexus', label: 'Master Command Nexus', icon: ShieldCheck },
    { id: 'radar', label: 'Live Threat Radar', icon: Activity },
    { id: 'incidents', label: 'Incidents & ATT&CK', icon: GitCommit },
    { id: 'xai', label: 'XAI (TreeSHAP)', icon: Cpu },
    {
      id: 'soar',
      label: 'SOAR & HITL',
      icon: Workflow,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
    },
    { id: 'warroom', label: 'Multi-Agent War Room', icon: ShieldAlert },
    { id: 'mlops', label: 'MLOps & Drift', icon: Layers },
    { id: 'chaos', label: 'Chaos & Resilience', icon: Flame },
    { id: 'deception', label: 'Deception & Decoys', icon: Eye },
    { id: 'zerotrust', label: 'Zero-Trust (ZTNA)', icon: Lock },
    { id: 'asm', label: 'Attack Surface (ASM)', icon: Target },
    { id: 'hunting', label: 'Threat Hunting (Sigma)', icon: Compass },
    { id: 'dfir', label: 'Forensics (DFIR)', icon: Archive },
    { id: 'bas', label: 'Breach Simulation (BAS)', icon: Swords },
    { id: 'paths', label: 'Attack Paths & Choke Points', icon: GitFork },
    { id: 'cspm', label: 'Cloud Posture (CSPM)', icon: Cloud },
    { id: 'sca', label: 'Supply Chain (SBOM)', icon: Package },
    { id: 'simulator', label: 'Cyber Range Simulator', icon: Crosshair },
  ];

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & System Title */}
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-slate-100 tracking-wider text-sm sm:text-base font-mono">
                  CYBERDEFENSE // SOC COMMAND
                </span>
                <span className="px-2 py-0.5 text-xs font-mono font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  SIMULATION SAFE
                </span>
              </div>
              <h1 className="text-base font-bold tracking-wider text-slate-100 uppercase font-mono">
                CyberDefense<span className="text-cyan-400">SOC</span>
              </h1>
              <p className="text-xs text-slate-400 font-mono hidden sm:block">
                Autonomous AI Defense & Multi-Agent SOC
              </p>
            </div>
          </div>

          {/* Status Indicators & Action */}
          <div className="flex items-center space-x-3">
            {onOpenReportsModal && (
              <button
                onClick={onOpenReportsModal}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-sky-600/20 border border-sky-500/40 text-sky-400 hover:bg-sky-600/30 text-xs font-semibold transition"
                title="Export Security Reports & Dossiers"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <span className="hidden sm:inline">Export Reports</span>
              </button>
            )}

            <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-xs font-mono">
              <Radio
                className={`w-3.5 h-3.5 ${
                  wsStatus === 'CONNECTED'
                    ? 'text-emerald-400 animate-pulse'
                    : wsStatus === 'CONNECTING'
                    ? 'text-yellow-400'
                    : 'text-rose-400'
                }`}
              />
              <span className="text-slate-300">STREAM:</span>
              <span
                className={`font-semibold ${
                  wsStatus === 'CONNECTED'
                    ? 'text-emerald-400'
                    : wsStatus === 'CONNECTING'
                    ? 'text-yellow-400'
                    : 'text-rose-400'
                }`}
              >
                {wsStatus}
              </span>
            </div>

            <button
              onClick={onRefresh}
              className="p-2 rounded-lg bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition"
              title="Refresh Data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-1 overflow-x-auto py-2 scrollbar-none">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium font-mono whitespace-nowrap transition relative ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.badge !== undefined && (
                  <span className="ml-1 px-1.5 py-0.2 rounded-full bg-rose-500 text-white text-[10px] font-bold">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};

