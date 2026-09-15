import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { LiveRadarView } from './components/LiveRadarView';
import { IncidentsTimelineView } from './components/IncidentsTimelineView';
import { XaiInspectorView } from './components/XaiInspectorView';
import { SoarApprovalView } from './components/SoarApprovalView';
import { InvestigationWarRoomView } from './components/InvestigationWarRoomView';
import { CyberRangeControls } from './components/CyberRangeControls';
import { ReportExportModal } from './components/ReportExportModal';
import { MlopsDashboardView } from './components/MlopsDashboardView';
import { ChaosEngineeringView } from './components/ChaosEngineeringView';
import { CyberDeceptionView } from './components/CyberDeceptionView';
import { ZeroTrustConsoleView } from './components/ZeroTrustConsoleView';
import { AttackSurfaceView } from './components/AttackSurfaceView';
import { ThreatHuntingView } from './components/ThreatHuntingView';
import { DfirConsoleView } from './components/DfirConsoleView';
import { BreachSimulationView } from './components/BreachSimulationView';
import { AttackPathView } from './components/AttackPathView';
import { CloudPostureView } from './components/CloudPostureView';
import { SupplyChainView } from './components/SupplyChainView';
import { MasterNexusView } from './components/MasterNexusView';
import { api } from './services/api';
import { socWebSocket } from './services/websocket';
import { Alert, Incident, ResponseAction, Playbook, Investigation, SOARStats } from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('nexus');
  const [wsStatus, setWsStatus] = useState<'CONNECTED' | 'CONNECTING' | 'DISCONNECTED'>('CONNECTING');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [soarStats, setSoarStats] = useState<SOARStats | null>(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [selectedReportIncidentId, setSelectedReportIncidentId] = useState<string>('');

  const loadAllData = useCallback(async () => {
    const [fetchedAlerts, fetchedIncidents, fetchedActions, fetchedPlaybooks, fetchedInvs, fetchedStats] =
      await Promise.all([
        api.getAlerts(100),
        api.getIncidents(),
        api.getSoarActions(),
        api.getPlaybooks(),
        api.getInvestigations(),
        api.getSoarStats(),
      ]);

    setAlerts(fetchedAlerts);
    setIncidents(fetchedIncidents);
    setActions(fetchedActions);
    setPlaybooks(fetchedPlaybooks);
    setInvestigations(fetchedInvs);
    setSoarStats(fetchedStats);
  }, []);

  useEffect(() => {
    loadAllData();

    socWebSocket.connect();
    const unsubStatus = socWebSocket.onStatusChange((status) => {
      setWsStatus(status);
    });

    const unsubMsg = socWebSocket.onMessage((msg) => {
      if (msg.type === 'NEW_SECURITY_INCIDENT' || msg.type === 'INCIDENT_ESCALATED') {
        loadAllData();
      } else if (msg.type === 'INVESTIGATION_COMPLETED') {
        loadAllData();
      } else if (msg.type === 'SOAR_PLAYBOOK_EXECUTED') {
        loadAllData();
      } else if (msg.event_id || msg.alert_id) {
        // New streaming alert
        const newAlert: Alert = {
          id: msg.alert_id || msg.event_id,
          title: msg.title || msg.attack_type || 'Stream Alert',
          severity: msg.severity || 'MEDIUM',
          status: 'ACTIVE',
          source_ip: msg.source_ip,
          destination_ip: msg.destination_ip,
          confidence: msg.confidence,
          attack_category: msg.attack_type,
          created_at: msg.timestamp || new Date().toISOString(),
        };
        setAlerts((prev) => [newAlert, ...prev.slice(0, 99)]);
      }
    });

    return () => {
      unsubStatus();
      unsubMsg();
      socWebSocket.disconnect();
    };
  }, [loadAllData]);

  const pendingApprovalsCount = actions.filter((a) => a.status === 'PENDING_APPROVAL').length;

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        wsStatus={wsStatus}
        onRefresh={loadAllData}
        pendingApprovalsCount={pendingApprovalsCount}
        onOpenReportsModal={() => {
          setSelectedReportIncidentId('');
          setIsReportModalOpen(true);
        }}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'nexus' && <MasterNexusView onNavigate={(tab) => setActiveTab(tab)} />}
        {activeTab === 'radar' && <LiveRadarView alerts={alerts} />}
        {activeTab === 'incidents' && (
          <IncidentsTimelineView
            incidents={incidents}
            onTriggerInvestigation={async (incidentId) => {
              await api.triggerInvestigation(incidentId);
              await loadAllData();
              setActiveTab('warroom');
            }}
          />
        )}
        {activeTab === 'xai' && <XaiInspectorView />}
        {activeTab === 'soar' && (
          <SoarApprovalView
            actions={actions}
            playbooks={playbooks}
            stats={soarStats}
            onRefresh={loadAllData}
          />
        )}
        {activeTab === 'warroom' && (
          <InvestigationWarRoomView
            investigations={investigations}
            onRefresh={loadAllData}
          />
        )}
        {activeTab === 'mlops' && <MlopsDashboardView />}
        {activeTab === 'chaos' && <ChaosEngineeringView />}
        {activeTab === 'deception' && <CyberDeceptionView />}
        {activeTab === 'zerotrust' && <ZeroTrustConsoleView />}
        {activeTab === 'asm' && <AttackSurfaceView />}
        {activeTab === 'hunting' && <ThreatHuntingView />}
        {activeTab === 'dfir' && <DfirConsoleView />}
        {activeTab === 'bas' && <BreachSimulationView />}
        {activeTab === 'paths' && <AttackPathView />}
        {activeTab === 'cspm' && <CloudPostureView />}
        {activeTab === 'sca' && <SupplyChainView />}
        {activeTab === 'simulator' && (
          <CyberRangeControls onScenarioTriggered={loadAllData} />
        )}
      </main>

      <ReportExportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        incidents={incidents}
        selectedIncidentId={selectedReportIncidentId}
      />

      <footer className="border-t border-slate-800/80 py-4 text-center text-xs font-mono text-slate-500 bg-slate-950">
        AUTONOMOUS AI CYBER DEFENSE PLATFORM &bull; DEFENSIVE ONLY &bull; MULTI-AGENT SOC &bull; SIMULATION SAFE
      </footer>
    </div>
  );
};


