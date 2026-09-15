import {
  Alert,
  Incident,
  AttackTimeline,
  XaiExplanation,
  ResponseAction,
  Playbook,
  Investigation,
  SOARStats,
  DriftEvaluationResponse,
  MLModel,
  ModelVersion,
  RetrainResponse,
  ChaosExperiment,
  ChaosStatus,
  AdversarialEvaluateResponse,
  Honeytoken,
  DecoyService,
  DeceptionMetrics,
  HoneytokenTripwireResponse,
  HoneytokenType,
  ZeroTrustMetrics,
  ContextualAccessDecision,
  MicrosegmentationPolicy,
  StepUpChallenge,
  DiscoveredAsset,
  PrioritizedVulnerability,
  AsmMetrics,
  AssetScanResponse,
  HuntHypothesis,
  HuntExecutionResult,
  DetectionRule,
  ThreatHuntingMetrics,
  ForensicArtifact,
  IntegrityVerificationResult,
  ForensicCase,
  CustodyCertificate,
  DfirMetrics,
  AptCampaignProfile,
  SimulationResult,
  CoverageMatrixItem,
  BasMetrics,
  CrownJewel,
  AttackPath,
  ChokePoint,
  ChokePointRemediationResult,
  ExposureMetrics,
  CloudFinding,
  CspmPolicy,
  IacPatch,
  CspmRemediationResult,
  CspmMetrics,
  SbomSummary,
  PackageComponent,
  ScaVulnerability,
  SupplyChainThreat,
  LicenseRisk,
  ScaRemediationPatch,
  ScaRemediationResult,
  ScaMetrics,
  MasterPosture,
  EmergencyLockdownResult,
  PlatformDiagnostics,
} from '../types';

const BASE_URL = '/api/v1';

export const api = {
  // Alerts & Incidents
  async getAlerts(limit = 50): Promise<Alert[]> {
    try {
      const res = await fetch(`${BASE_URL}/alerts?limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getIncidents(): Promise<Incident[]> {
    try {
      const res = await fetch(`${BASE_URL}/incidents`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getIncidentTimeline(incidentId: string): Promise<AttackTimeline[]> {
    try {
      const res = await fetch(`${BASE_URL}/incidents/${incidentId}/timeline`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  // Detection & XAI
  async classifyFlow(payload: Record<string, any>): Promise<{
    prediction: string;
    attack_type: string;
    confidence: number;
    severity: string;
    xai_explanation: XaiExplanation;
  }> {
    const res = await fetch(`${BASE_URL}/detection/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Classification failed');
    return await res.json();
  },

  // SOAR Response & Playbooks
  async getSoarActions(): Promise<ResponseAction[]> {
    try {
      const res = await fetch(`${BASE_URL}/response/actions`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async approveAction(actionId: string, comments = 'Approved via SOC Dashboard'): Promise<any> {
    const res = await fetch(`${BASE_URL}/response/actions/${actionId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: 'APPROVED', comments }),
    });
    return await res.json();
  },

  async rejectAction(actionId: string, comments = 'Rejected by SOC Analyst'): Promise<any> {
    const res = await fetch(`${BASE_URL}/response/actions/${actionId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: 'REJECTED', comments }),
    });
    return await res.json();
  },

  async rollbackAction(actionId: string): Promise<any> {
    const res = await fetch(`${BASE_URL}/response/actions/${actionId}/rollback`, {
      method: 'POST',
    });
    return await res.json();
  },

  async getPlaybooks(): Promise<Playbook[]> {
    try {
      const res = await fetch(`${BASE_URL}/response/playbooks`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async executePlaybook(playbookId: string, incidentId: string, isSimulation = true): Promise<any> {
    const res = await fetch(`${BASE_URL}/response/playbooks/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        playbook_id: playbookId,
        incident_id: incidentId,
        is_simulation: isSimulation,
      }),
    });
    return await res.json();
  },

  async getSoarStats(): Promise<SOARStats | null> {
    try {
      const res = await fetch(`${BASE_URL}/response/stats`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Multi-Agent Investigations
  async getInvestigations(): Promise<Investigation[]> {
    try {
      const res = await fetch(`${BASE_URL}/investigations`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async triggerInvestigation(incidentId: string, analystId = 'soc_operator'): Promise<Investigation> {
    const res = await fetch(`${BASE_URL}/investigations/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident_id: incidentId, analyst_id: analystId, priority: 'HIGH' }),
    });
    if (!res.ok) throw new Error('Investigation trigger failed');
    return await res.json();
  },

  // Cyber Range Simulator
  async getScenarios(): Promise<any[]> {
    try {
      const res = await fetch(`${BASE_URL}/simulation/scenarios`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async runScenario(scenarioId: number, durationSeconds = 15): Promise<any> {
    const res = await fetch(`${BASE_URL}/simulation/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario_id: scenarioId, duration_seconds: durationSeconds }),
    });
    return await res.json();
  },

  // Security Reporting
  async generateReport(payload: {
    incident_id?: string;
    report_type?: string;
    format?: string;
    title?: string;
  }): Promise<any> {
    const res = await fetch(`${BASE_URL}/reports/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to generate report');
    return await res.json();
  },

  async getReports(): Promise<any[]> {
    try {
      const res = await fetch(`${BASE_URL}/reports`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  getReportDownloadUrl(reportId: string): string {
    return `${BASE_URL}/reports/${reportId}/download`;
  },

  // Continuous MLOps & Model Governance
  async getDriftMetrics(): Promise<DriftEvaluationResponse | null> {
    try {
      const res = await fetch(`${BASE_URL}/mlops/drift`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async evaluateDrift(sampleCount = 200, introduceDrift = false): Promise<DriftEvaluationResponse | null> {
    try {
      const res = await fetch(`${BASE_URL}/mlops/drift/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_count: sampleCount, introduce_drift: introduceDrift }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getMlModels(): Promise<MLModel[]> {
    try {
      const res = await fetch(`${BASE_URL}/mlops/models`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getModelVersions(modelId: string): Promise<ModelVersion[]> {
    try {
      const res = await fetch(`${BASE_URL}/mlops/models/${modelId}/versions`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async promoteModelVersion(versionId: string): Promise<ModelVersion | null> {
    try {
      const res = await fetch(`${BASE_URL}/mlops/models/${versionId}/promote`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async triggerRetraining(triggerReason = 'MANUAL', autoPromote = true): Promise<RetrainResponse | null> {
    try {
      const res = await fetch(`${BASE_URL}/mlops/retrain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ trigger_reason: triggerReason, auto_promote: autoPromote }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Security Chaos Engineering & Adversarial Resilience
  async getChaosStatus(): Promise<ChaosStatus | null> {
    try {
      const res = await fetch(`${BASE_URL}/chaos/status`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getChaosExperiments(): Promise<ChaosExperiment[]> {
    try {
      const res = await fetch(`${BASE_URL}/chaos/experiments`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async injectChaos(
    experimentType: string,
    durationSeconds = 30,
    params: Record<string, any> = {}
  ): Promise<ChaosExperiment | null> {
    try {
      const res = await fetch(`${BASE_URL}/chaos/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          experiment_type: experimentType,
          duration_seconds: durationSeconds,
          params,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async recoverChaos(experimentId?: string): Promise<ChaosExperiment[]> {
    try {
      const res = await fetch(`${BASE_URL}/chaos/recover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(experimentId ? { experiment_id: experimentId } : {}),
      });
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async evaluateAdversarial(
    perturbationEpsilon = 0.15,
    technique = 'BENIGN_MIMICRY'
  ): Promise<AdversarialEvaluateResponse | null> {
    try {
      const res = await fetch(`${BASE_URL}/chaos/adversarial/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          perturbation_epsilon: perturbationEpsilon,
          technique,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Cyber Deception, Honeytokens & Decoy Network
  async getDeceptionMetrics(): Promise<DeceptionMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/deception/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getHoneytokens(): Promise<Honeytoken[]> {
    try {
      const res = await fetch(`${BASE_URL}/deception/tokens`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async deployHoneytoken(
    tokenType: HoneytokenType,
    name: string,
    baitPath?: string,
    metadata?: Record<string, any>
  ): Promise<Honeytoken | null> {
    try {
      const res = await fetch(`${BASE_URL}/deception/tokens/deploy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token_type: tokenType,
          name,
          bait_path: baitPath,
          metadata: metadata || {},
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async triggerHoneytokenTripwire(
    tokenValueOrId: string,
    sourceIp = '192.168.1.185',
    userAgent = 'python-requests/2.31.0 (Adversary Recon Scanner)'
  ): Promise<HoneytokenTripwireResponse | null> {
    try {
      const res = await fetch(`${BASE_URL}/deception/tokens/tripwire`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token_value_or_id: tokenValueOrId,
          source_ip: sourceIp,
          user_agent: userAgent,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async revokeHoneytoken(tokenId: string): Promise<Honeytoken | null> {
    try {
      const res = await fetch(`${BASE_URL}/deception/tokens/${tokenId}/revoke`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getDecoyServices(): Promise<DecoyService[]> {
    try {
      const res = await fetch(`${BASE_URL}/deception/decoys`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async interactWithDecoy(
    decoyId: string,
    commandOrPayload: string,
    sourceIp = '192.168.1.185'
  ): Promise<any | null> {
    try {
      const res = await fetch(`${BASE_URL}/deception/decoys/${decoyId}/interact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command_or_payload: commandOrPayload,
          source_ip: sourceIp,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Zero-Trust Adaptive Access Control & ZTNA
  async getZeroTrustMetrics(): Promise<ZeroTrustMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/zerotrust/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async evaluateZeroTrustAccess(
    req: Record<string, any>
  ): Promise<ContextualAccessDecision | null> {
    try {
      const res = await fetch(`${BASE_URL}/zerotrust/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getMicrosegmentationPolicies(): Promise<MicrosegmentationPolicy[]> {
    try {
      const res = await fetch(`${BASE_URL}/zerotrust/policies`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async createMicrosegmentationPolicy(
    policy: Record<string, any>
  ): Promise<MicrosegmentationPolicy | null> {
    try {
      const res = await fetch(`${BASE_URL}/zerotrust/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(policy),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async toggleMicrosegmentationPolicy(
    policyId: string
  ): Promise<MicrosegmentationPolicy | null> {
    try {
      const res = await fetch(`${BASE_URL}/zerotrust/policies/${policyId}/toggle`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async triggerStepUpChallenge(
    sessionId: string
  ): Promise<StepUpChallenge | null> {
    try {
      const res = await fetch(`${BASE_URL}/zerotrust/sessions/${sessionId}/step-up`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Attack Surface Management & RBVM (Phase 18)
  async getAsmMetrics(): Promise<AsmMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/asm/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getAsmAssets(exposure?: string): Promise<DiscoveredAsset[]> {
    try {
      const url = exposure ? `${BASE_URL}/asm/assets?exposure=${exposure}` : `${BASE_URL}/asm/assets`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async triggerAsmScan(
    subnetRange = '10.0.0.0/16',
    scanIntensity = 'COMPREHENSIVE'
  ): Promise<AssetScanResponse | null> {
    try {
      const res = await fetch(`${BASE_URL}/asm/assets/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subnet_range: subnetRange,
          scan_intensity: scanIntensity,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getPrioritizedVulnerabilities(
    status?: string,
    priority?: string
  ): Promise<PrioritizedVulnerability[]> {
    try {
      const params = new URLSearchParams();
      if (status) params.append('status', status);
      if (priority) params.append('priority', priority);
      const url = params.toString() ? `${BASE_URL}/asm/vulnerabilities?${params.toString()}` : `${BASE_URL}/asm/vulnerabilities`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async recalculateVulnerabilityPriorities(
    recalculate = true
  ): Promise<PrioritizedVulnerability[]> {
    try {
      const res = await fetch(`${BASE_URL}/asm/vulnerabilities/prioritize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recalculate }),
      });
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async remediateVulnerability(
    cveId: string,
    resolutionNotes = 'Automated SOAR virtual patch applied',
    action = 'APPLY_VIRTUAL_PATCH'
  ): Promise<PrioritizedVulnerability | null> {
    try {
      const res = await fetch(`${BASE_URL}/asm/vulnerabilities/${cveId}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resolution_notes: resolutionNotes,
          action,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Threat Hunting & Detection-as-Code (Phase 19)
  async getThreatHuntingMetrics(): Promise<ThreatHuntingMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/threathunting/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getHuntHypotheses(): Promise<HuntHypothesis[]> {
    try {
      const res = await fetch(`${BASE_URL}/threathunting/hypotheses`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async executeHunt(
    hypothesisId: string,
    timeWindowHours = 24
  ): Promise<HuntExecutionResult | null> {
    try {
      const res = await fetch(`${BASE_URL}/threathunting/hunts/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hypothesis_id: hypothesisId,
          time_window_hours: timeWindowHours,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getHuntHistory(): Promise<HuntExecutionResult[]> {
    try {
      const res = await fetch(`${BASE_URL}/threathunting/hunts/history`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getDetectionRules(
    format?: string,
    status?: string
  ): Promise<DetectionRule[]> {
    try {
      const params = new URLSearchParams();
      if (format) params.append('format', format);
      if (status) params.append('status', status);
      const url = params.toString()
        ? `${BASE_URL}/threathunting/rules?${params.toString()}`
        : `${BASE_URL}/threathunting/rules`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async generateDetectionRule(
    hypothesisId: string,
    ruleFormat = 'SIGMA_YAML',
    title?: string,
    severity = 'high'
  ): Promise<DetectionRule | null> {
    try {
      const res = await fetch(`${BASE_URL}/threathunting/rules/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hypothesis_id: hypothesisId,
          rule_format: ruleFormat,
          title,
          severity,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async deployDetectionRule(ruleId: string): Promise<DetectionRule | null> {
    try {
      const res = await fetch(`${BASE_URL}/threathunting/rules/${ruleId}/deploy`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Digital Forensics & Incident Response (DFIR) (Phase 20)
  async getDfirMetrics(): Promise<DfirMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/dfir/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getDfirCases(): Promise<ForensicCase[]> {
    try {
      const res = await fetch(`${BASE_URL}/dfir/cases`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getDfirArtifacts(
    caseId?: string,
    artifactType?: string
  ): Promise<ForensicArtifact[]> {
    try {
      const params = new URLSearchParams();
      if (caseId) params.append('case_id', caseId);
      if (artifactType) params.append('artifact_type', artifactType);
      const url = params.toString()
        ? `${BASE_URL}/dfir/artifacts?${params.toString()}`
        : `${BASE_URL}/dfir/artifacts`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async acquireDfirArtifact(
    data: Record<string, any>
  ): Promise<ForensicArtifact | null> {
    try {
      const res = await fetch(`${BASE_URL}/dfir/artifacts/acquire`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async verifyDfirIntegrity(
    artifactId: string,
    tamperTest = false
  ): Promise<IntegrityVerificationResult | null> {
    try {
      const url = tamperTest
        ? `${BASE_URL}/dfir/artifacts/${artifactId}/verify?tamper_test=true`
        : `${BASE_URL}/dfir/artifacts/${artifactId}/verify`;
      const res = await fetch(url, { method: 'POST' });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async transferDfirCustody(
    artifactId: string,
    newCustodian: string,
    purpose: string
  ): Promise<ForensicArtifact | null> {
    try {
      const res = await fetch(`${BASE_URL}/dfir/artifacts/${artifactId}/transfer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          new_custodian: newCustodian,
          purpose,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getDfirCertificate(caseId: string): Promise<CustodyCertificate | null> {
    try {
      const res = await fetch(`${BASE_URL}/dfir/cases/${caseId}/certificate`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Breach and Attack Simulation (BAS) (Phase 21)
  async getBasMetrics(): Promise<BasMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/bas/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getBasCampaigns(): Promise<AptCampaignProfile[]> {
    try {
      const res = await fetch(`${BASE_URL}/bas/campaigns`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getBasCampaign(campaignId: string): Promise<AptCampaignProfile | null> {
    try {
      const res = await fetch(`${BASE_URL}/bas/campaigns/${campaignId}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async executeBasCampaign(
    campaignId: string,
    targetEnvironment = 'Simulated Multi-VPC Cloud & On-Premises Range',
    dryRun = false
  ): Promise<SimulationResult | null> {
    try {
      const res = await fetch(`${BASE_URL}/bas/campaigns/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          campaign_id: campaignId,
          target_environment: targetEnvironment,
          dry_run: dryRun,
        }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getBasSimulations(limit = 50): Promise<SimulationResult[]> {
    try {
      const res = await fetch(`${BASE_URL}/bas/simulations?limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getBasCoverageMatrix(): Promise<CoverageMatrixItem[]> {
    try {
      const res = await fetch(`${BASE_URL}/bas/coverage-matrix`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  // Cyber Threat Exposure & Attack Path Validation (Phase 22)
  async getExposureMetrics(): Promise<ExposureMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/exposure/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getCrownJewels(): Promise<CrownJewel[]> {
    try {
      const res = await fetch(`${BASE_URL}/exposure/crown-jewels`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getAttackPaths(): Promise<AttackPath[]> {
    try {
      const res = await fetch(`${BASE_URL}/exposure/attack-paths`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getChokePoints(): Promise<ChokePoint[]> {
    try {
      const res = await fetch(`${BASE_URL}/exposure/choke-points`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async remediateChokePoint(chokePointId: string): Promise<ChokePointRemediationResult | null> {
    try {
      const res = await fetch(`${BASE_URL}/exposure/choke-points/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ choke_point_id: chokePointId }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async resetExposureGraph(): Promise<any> {
    try {
      const res = await fetch(`${BASE_URL}/exposure/reset`, { method: 'POST' });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Cloud Security Posture Management (CSPM) & IaC Guard (Phase 23)
  async getCspmMetrics(): Promise<CspmMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/cspm/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getCspmPolicies(): Promise<CspmPolicy[]> {
    try {
      const res = await fetch(`${BASE_URL}/cspm/policies`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getCspmFindings(
    provider?: string,
    severity?: string,
    status?: string
  ): Promise<CloudFinding[]> {
    try {
      const params = new URLSearchParams();
      if (provider) params.append('provider', provider);
      if (severity) params.append('severity', severity);
      if (status) params.append('status', status);
      const query = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`${BASE_URL}/cspm/findings${query}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getCspmFinding(findingId: string): Promise<CloudFinding | null> {
    try {
      const res = await fetch(`${BASE_URL}/cspm/findings/${findingId}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getCspmFindingPatch(findingId: string): Promise<IacPatch | null> {
    try {
      const res = await fetch(`${BASE_URL}/cspm/findings/${findingId}/patch`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async remediateCspmFinding(findingId: string): Promise<CspmRemediationResult | null> {
    try {
      const res = await fetch(`${BASE_URL}/cspm/findings/${findingId}/remediate`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async resetCspmFindings(): Promise<any> {
    try {
      const res = await fetch(`${BASE_URL}/cspm/reset`, { method: 'POST' });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Software Supply Chain Security (SCA) & SBOM Governance
  async getScaMetrics(): Promise<ScaMetrics | null> {
    try {
      const res = await fetch(`${BASE_URL}/sca/metrics`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getSboms(): Promise<SbomSummary[]> {
    try {
      const res = await fetch(`${BASE_URL}/sca/sboms`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async exportCycloneDxSbom(sbomId: string): Promise<any> {
    try {
      const res = await fetch(`${BASE_URL}/sca/sboms/${sbomId}/export`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async getScaComponents(
    ecosystem?: string,
    isDirect?: boolean,
    sbomId?: string
  ): Promise<PackageComponent[]> {
    try {
      const params = new URLSearchParams();
      if (ecosystem) params.append('ecosystem', ecosystem);
      if (isDirect !== undefined) params.append('is_direct', String(isDirect));
      if (sbomId) params.append('sbom_id', sbomId);
      const query = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`${BASE_URL}/sca/components${query}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getScaVulnerabilities(
    severity?: string,
    cisaKevOnly?: boolean,
    status?: string,
    reachability?: string
  ): Promise<ScaVulnerability[]> {
    try {
      const params = new URLSearchParams();
      if (severity) params.append('severity', severity);
      if (cisaKevOnly) params.append('cisa_kev_only', 'true');
      if (status) params.append('status', status);
      if (reachability) params.append('reachability', reachability);
      const query = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`${BASE_URL}/sca/vulnerabilities${query}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getScaThreats(): Promise<SupplyChainThreat[]> {
    try {
      const res = await fetch(`${BASE_URL}/sca/threats`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getScaLicenses(): Promise<LicenseRisk[]> {
    try {
      const res = await fetch(`${BASE_URL}/sca/licenses`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  async getScaPatch(vulnId: string): Promise<ScaRemediationPatch | null> {
    try {
      const res = await fetch(`${BASE_URL}/sca/vulnerabilities/${vulnId}/patch`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async remediateSca(vulnId: string): Promise<ScaRemediationResult | null> {
    try {
      const res = await fetch(`${BASE_URL}/sca/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln_id: vulnId }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  // Master SOC Command Nexus (Flagship)
  async getNexusPosture(): Promise<MasterPosture | null> {
    try {
      const res = await fetch(`${BASE_URL}/nexus/posture`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async triggerEmergencyLockdown(
    operator = 'SOC_COMMANDER',
    reason = 'COORDINATED_APT_CONTAINMENT'
  ): Promise<EmergencyLockdownResult | null> {
    try {
      const res = await fetch(`${BASE_URL}/nexus/emergency-lockdown`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operator, reason }),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async liftEmergencyLockdown(): Promise<any> {
    try {
      const res = await fetch(`${BASE_URL}/nexus/lift-lockdown`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  async runPlatformDiagnostics(): Promise<PlatformDiagnostics | null> {
    try {
      const res = await fetch(`${BASE_URL}/nexus/run-diagnostics`, {
        method: 'POST',
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },
};



