export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Alert {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  created_at: string;
  confidence?: number;
  attack_category?: string;
}

export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: Severity;
  attack_stage: string;
  composite_risk_score: number;
  status: string;
  created_at: string;
  timeline?: AttackTimeline[];
}

export interface AttackTimeline {
  id: string;
  incident_id: string;
  timestamp: string;
  event_summary: string;
  entity: string;
  detection_source: string;
  mitre_technique?: string;
  severity: Severity;
}

export interface XaiFactor {
  rank: number;
  feature: string;
  raw_value: number;
  shap_attribution: number;
  impact: 'INCREASED_RISK' | 'DECREASED_RISK';
  description: string;
}

export interface XaiExplanation {
  predicted_category: string;
  explanation_method: string;
  contributing_factors: XaiFactor[];
  deterministic_summary: string;
}

export interface ResponseAction {
  id: string;
  incident_id: string;
  action_type: string;
  target_entity: string;
  is_simulation: boolean;
  status: string;
  rationale: string;
  risk_impact_score: number;
  created_at: string;
  executed_at?: string;
}

export interface PlaybookStep {
  step_id: string;
  name: string;
  action_type: string;
  target_field: string;
  risk_impact_score: number;
  requires_approval: boolean;
  rollback_on_failure: boolean;
}

export interface Playbook {
  playbook_id: string;
  name: string;
  description: string;
  trigger_criteria: Record<string, any>;
  steps: PlaybookStep[];
  enabled: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  source: string;
  entity_type: string;
  entity_value: string;
  description: string;
  raw_data?: Record<string, any>;
}

export interface HypothesisItem {
  hypothesis_id: string;
  claim: string;
  supporting_evidence_ids: string[];
  confidence: number;
  risk_level: string;
  recommended_action?: string;
}

export interface ScratchpadEntry {
  agent_role: string;
  thought_process: string;
  action_taken: string;
  observations: string;
  timestamp: string;
}

export interface Investigation {
  id: string;
  incident_id: string;
  analyst_id?: string;
  status: string;
  observed_evidence: { items?: EvidenceItem[]; count?: number };
  inferred_hypotheses: { items?: HypothesisItem[]; count?: number };
  agent_scratchpad: Record<string, ScratchpadEntry[]>;
  executive_summary?: string;
  technical_analysis?: string;
  recommended_playbook?: string;
  false_positive_probability?: number;
  created_at: string;
  completed_at?: string;
}

export interface SOARStats {
  total_actions: number;
  pending_approval_count: number;
  executed_count: number;
  rejected_count: number;
  failed_count: number;
  active_playbooks_count: number;
  simulation_mode_enabled: boolean;
  hitl_required: boolean;
}

export type ReportType = 'EXECUTIVE_SUMMARY' | 'TECHNICAL_FORENSIC_DOSSIER' | 'INCIDENT_POST_MORTEM' | 'COMPLIANCE_AUDIT';
export type ReportFormat = 'HTML' | 'MARKDOWN' | 'JSON' | 'CSV';

export interface SecurityReport {
  id: string;
  title: string;
  report_type: ReportType;
  format: ReportFormat;
  status: string;
  incident_id?: string;
  generated_by_user_id?: string;
  metadata_json: Record<string, any>;
  file_size_bytes: number;
  created_at: string;
}

export interface FeatureDriftDetail {
  feature: string;
  psi: number;
  ks_statistic: number;
  ks_pvalue: number;
  baseline_mean: number;
  current_mean: number;
  baseline_std: number;
  current_std: number;
  drift_detected: boolean;
  status: 'STABLE' | 'WARNING' | 'CRITICAL';
}

export interface DriftEvaluationResponse {
  drift_detected: boolean;
  status: 'STABLE' | 'WARNING' | 'CRITICAL';
  mean_psi: number;
  max_psi: number;
  drifted_features_count: number;
  total_features_evaluated: number;
  drifted_features: string[];
  feature_metrics: Record<string, FeatureDriftDetail>;
  evaluated_at: string;
}

export interface ModelVersion {
  id: string;
  model_id: string;
  version: string;
  validation_f1: number;
  validation_precision: number;
  validation_recall: number;
  artifact_path: string;
  is_deployed: boolean;
  trained_at: string;
}

export interface MLModel {
  id: string;
  model_name: string;
  model_family: string;
  active_version?: string;
  created_at: string;
  versions: ModelVersion[];
}

export interface RetrainResponse {
  job_id: string;
  version: string;
  trigger_reason: string;
  training_samples: number;
  validation_samples: number;
  models_evaluated: Record<string, any>;
  status: string;
  completed_at: string;
}

export type ChaosType = 'BROKER_LATENCY' | 'BROKER_DROP' | 'DB_PARTITION' | 'AGENT_TIMEOUT' | 'TELEMETRY_BURST';

export interface ChaosExperiment {
  id: string;
  experiment_type: ChaosType;
  status: 'ACTIVE' | 'RECOVERED' | 'EXPIRED';
  duration_seconds: number;
  started_at: string;
  expires_at: string;
  params: Record<string, any>;
  metrics: Record<string, any>;
}

export interface ChaosStatus {
  resilience_score: number;
  system_state: 'STEADY_STATE' | 'CHAOS_INJECTED';
  active_faults_count: number;
  mean_time_to_recovery_ms: number;
  zero_downtime_guaranteed: boolean;
  in_memory_fallbacks_operational: boolean;
  active_experiments: ChaosExperiment[];
  last_evaluated_at: string;
}

export interface AdversarialModelBenchmark {
  model_name: string;
  clean_accuracy: number;
  adversarial_accuracy: number;
  evasions_detected_as_benign: number;
  evasion_success_rate: number;
  adversarial_robustness_index: number;
  robustness_grade: 'A' | 'B' | 'C';
}

export interface AdversarialEvaluateResponse {
  total_attack_samples_tested: number;
  perturbation_epsilon: number;
  technique_applied: string;
  ensemble_adversarial_robustness_index: number;
  ensemble_robustness_grade: 'A' | 'B' | 'C';
  models: Record<string, AdversarialModelBenchmark>;
}

export type HoneytokenType =
  | 'API_KEY'
  | 'DATABASE_CREDENTIAL'
  | 'AWS_SECRET_KEY'
  | 'JWT_TOKEN'
  | 'CANARY_FILE'
  | 'SSH_KEY';

export interface Honeytoken {
  id: string;
  name: string;
  token_type: HoneytokenType;
  token_value?: string;
  masked_value: string;
  bait_path: string;
  status: 'ACTIVE' | 'TRIPPED' | 'REVOKED';
  hit_count: number;
  created_at: string;
  last_tripped_at?: string;
  last_attacker_ip?: string;
  last_user_agent?: string;
  metadata: Record<string, any>;
}

export interface DecoyInteractionEntry {
  interaction_id: string;
  decoy_id: string;
  source_ip: string;
  command_or_payload: string;
  simulated_output: string;
  captured_at: string;
}

export interface DecoyService {
  id: string;
  service_type: string;
  name: string;
  port: number;
  protocol: string;
  fake_banner: string;
  status: 'ONLINE' | 'ENGAGED' | 'OFFLINE';
  interaction_count: number;
  captured_payloads: DecoyInteractionEntry[];
}

export interface DeceptionMetrics {
  total_honeytokens_deployed: number;
  active_honeytokens: number;
  tripped_honeytokens: number;
  total_honeytoken_hits: number;
  total_decoys_online: number;
  engaged_decoys: number;
  total_decoy_interactions: number;
  true_positive_fidelity_percent: number;
  zero_false_positives_guaranteed: boolean;
  recent_tripwires: any[];
  evaluated_at: string;
}

export interface HoneytokenTripwireResponse {
  tripwire_triggered: boolean;
  token?: Honeytoken;
  alert?: Record<string, any>;
  error?: string;
}

export type AccessDecision = 'ALLOW' | 'STEP_UP_AUTH' | 'RESTRICT' | 'BLOCK';
export type ResourceSensitivity = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED_CROWN_JEWEL';
export type AuthAssuranceLevel = 'PASSWORD_ONLY' | 'PASSWORD_SMS' | 'HARDWARE_MFA_FIDO2';

export interface ContextualAccessDecision {
  evaluation_id: string;
  user_id: string;
  resource_id: string;
  resource_sensitivity: string;
  trust_score: number;
  decision: AccessDecision;
  reason: string;
  score_breakdown: Record<string, number>;
  evaluated_at: string;
}

export interface MicrosegmentationPolicy {
  id: string;
  name: string;
  source_subnet: string;
  destination_subnet: string;
  port_protocol: string;
  action: 'ALLOW' | 'DENY';
  is_enabled: boolean;
  description: string;
  created_at?: string;
}

export interface ZeroTrustMetrics {
  average_trust_score: number;
  active_policies_count: number;
  total_microsegmentation_policies: number;
  continuous_verification_rate_percent: number;
  active_sessions_monitored: number;
  total_evaluations_completed: number;
  blocked_access_attempts: number;
  nist_compliance_framework: string;
  evaluated_at: string;
}

export interface StepUpChallenge {
  challenge_id: string;
  session_id: string;
  status: string;
  required_auth: string;
  created_at: string;
  expires_at: string;
}

export type AssetCriticalityTier = 'TIER_1_MISSION_CRITICAL' | 'TIER_2_CORE_OPERATIONAL' | 'TIER_3_INTERNAL_SUPPORT';
export type ExposureLevel = 'INTERNET_FACING' | 'DMZ' | 'INTERNAL_SEGMENTED' | 'AIR_GAPPED';
export type VulnerabilityPriority = 'P0_CRITICAL' | 'P1_HIGH' | 'P2_MEDIUM' | 'P3_LOW';
export type VulnerabilityStatus = 'ACTIVE' | 'IN_REMEDIATION' | 'REMEDIATED' | 'RISK_ACCEPTED';

export interface DiscoveredAsset {
  id: string;
  hostname: string;
  ip_address: string;
  criticality: AssetCriticalityTier;
  exposure: ExposureLevel;
  environment: string;
  open_ports: number[];
  services: string[];
  active_vulnerabilities_count: number;
  has_zero_trust_control: boolean;
  owner_team: string;
  discovered_at: string;
}

export interface PrioritizedVulnerability {
  cve_id: string;
  title: string;
  cvss_score: number;
  epss_probability: number;
  contextual_risk_score: number;
  priority: VulnerabilityPriority;
  has_known_exploit: boolean;
  cisa_kev: boolean;
  asset_id: string;
  asset_hostname: string;
  affected_service: string;
  status: VulnerabilityStatus;
  sla_hours: number;
  sla_description: string;
  sla_deadline?: string;
  sla_breached?: boolean;
  score_breakdown?: Record<string, number>;
  resolution_notes?: string;
  remediated_at?: string;
  discovered_at: string;
}

export interface AsmMetrics {
  attack_surface_exposure_score: number;
  total_assets: number;
  internet_facing_assets: number;
  internal_assets: number;
  total_vulnerabilities: number;
  active_vulnerabilities: number;
  remediated_vulnerabilities: number;
  p0_critical_count: number;
  p1_high_count: number;
  avg_epss_probability: number;
  sla_compliance_rate: number;
  last_scan_timestamp: string;
}

export interface AssetScanResponse {
  scan_id: string;
  subnet_range: string;
  scan_intensity: string;
  assets_discovered: number;
  total_assets: number;
  completed_at: string;
}

export type RuleFormat = 'SIGMA_YAML' | 'YARA';
export type RuleStatus = 'DRAFT' | 'VALIDATED' | 'DEPLOYED_ACTIVE' | 'ARCHIVED';

export interface HuntHypothesis {
  id: string;
  title: string;
  tactic: string;
  mitre_technique: string;
  severity: string;
  description: string;
  data_sources: string[];
  target_telemetry: string;
  query_logic: string;
  base_confidence: number;
}

export interface HuntExecutionResult {
  execution_id: string;
  hypothesis_id: string;
  hypothesis_title: string;
  tactic: string;
  mitre_technique: string;
  time_window_hours: number;
  findings_count: number;
  confidence_score: number;
  confidence_level: string;
  matched_iocs: string[];
  affected_hosts: string[];
  query_executed: string;
  recommended_action: string;
  executed_at: string;
}

export interface DetectionRule {
  id: string;
  title: string;
  format: RuleFormat;
  status: RuleStatus;
  severity: string;
  mitre_technique: string;
  author: string;
  content: string;
  hypothesis_id?: string;
  created_at: string;
  deployed_at?: string;
}

export interface ThreatHuntingMetrics {
  total_hypotheses: number;
  total_hunts_executed: number;
  hypothesis_validation_rate: number;
  total_detection_rules: number;
  deployed_active_rules: number;
  sigma_rules_count: number;
  yara_rules_count: number;
  mean_hunt_dwell_reduction_percent: number;
  last_hunt_timestamp: string;
}

export type ArtifactType = 'VOLATILE_MEMORY' | 'NETWORK_PCAP' | 'DISK_FORENSICS' | 'TRIAGE_BUNDLE';
export type CustodyAction = 'ACCESSION_SEALED' | 'INTEGRITY_VERIFIED' | 'CUSTODY_TRANSFERRED' | 'ANALYSIS_CHECKOUT' | 'LEGAL_EXPORT';

export interface CustodyEvent {
  event_id: string;
  artifact_id: string;
  action: CustodyAction;
  timestamp: string;
  custodian: string;
  releasing_custodian?: string;
  purpose: string;
  sha256_verified: string;
  leaf_hash: string;
}

export interface ForensicArtifact {
  id: string;
  case_id: string;
  artifact_name: string;
  artifact_type: ArtifactType;
  affected_host: string;
  source_path: string;
  file_size_bytes: number;
  genesis_sha256: string;
  genesis_sha3_512: string;
  current_custodian: string;
  custody_chain_length: number;
  is_tamper_detected: boolean;
  notes?: string;
  accession_timestamp: string;
  last_verified_at: string;
}

export interface IntegrityVerificationResult {
  artifact_id: string;
  artifact_name: string;
  genesis_sha256: string;
  current_sha256: string;
  genesis_sha3_512: string;
  current_sha3_512: string;
  integrity_verified: boolean;
  tamper_detected: boolean;
  verification_timestamp: string;
  leaf_hash: string;
}

export interface ForensicCase {
  case_id: string;
  title: string;
  lead_examiner: string;
  incident_id: string;
  status: string;
  evidence_count: number;
  created_at: string;
}

export interface CustodyCertificate {
  certificate_id: string;
  case_id: string;
  standard_compliance: string;
  total_artifacts_certified: number;
  total_custody_events: number;
  merkle_root_hash: string;
  admissibility_status: string;
  certified_artifacts: any[];
  custody_events: any[];
  issued_at: string;
}

export interface DfirMetrics {
  total_artifacts: number;
  total_cases: number;
  total_evidence_size_bytes: number;
  verified_integrity_rate_percent: number;
  tamper_incidents_detected: number;
  total_custody_events: number;
  active_custodians_count: number;
  standard_framework: string;
  last_accession_timestamp: string;
}

export interface KillChainStageDetail {
  stage_id: string;
  stage_order: number;
  stage_name: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  execution_payload: string;
  default_detecting_layer: string;
  mitigation: string;
  severity: string;
  simulated_latency_ms: number;
  default_outcome: string;
}

export interface AptCampaignProfile {
  campaign_id: string;
  name: string;
  actor_alias: string;
  actor_origin: string;
  target_sectors: string[];
  description: string;
  complexity: string;
  estimated_duration_sec: number;
  stages: KillChainStageDetail[];
}

export interface StageResult {
  stage_id: string;
  stage_name: string;
  tactic: string;
  technique_id: string;
  technique_name: string;
  status: 'PREVENTED' | 'DETECTED' | 'EVADED';
  detecting_layer: string;
  mitigation: string;
  execution_time_ms: number;
  severity: string;
  payload_sample?: string;
}

export interface SimulationResult {
  simulation_id: string;
  campaign_id: string;
  campaign_name: string;
  target_environment: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  total_stages: number;
  prevented_stages: number;
  detected_stages: number;
  evaded_stages: number;
  prevention_rate_percent: number;
  detection_rate_percent: number;
  posture_score: number;
  mean_time_to_block_ms: number;
  summary_verdict: string;
  stage_results: StageResult[];
  dry_run?: boolean;
}

export interface CoverageMatrixItem {
  technique_id: string;
  technique_name: string;
  tactic: string;
  status: 'PREVENTED' | 'DETECTED' | 'EVADED';
  detecting_layer: string;
  campaigns_tested: string[];
  last_tested_at: string;
}

export interface BasMetrics {
  overall_posture_score: number;
  total_campaigns_available: number;
  total_simulations_executed: number;
  detection_rate_percent: number;
  prevention_rate_percent: number;
  mean_time_to_block_ms: number;
  mitre_techniques_covered: number;
  unmitigated_gaps_count: number;
  last_simulation_timestamp: string;
}

export interface CrownJewel {
  id: string;
  name: string;
  asset_tier: string;
  category: string;
  criticality_score: number;
  ip_address: string;
  hostname: string;
  data_classification: string;
  inbound_paths_count: number;
  is_isolated: boolean;
  compensating_controls: string[];
}

export interface AttackPathNode {
  step_order: number;
  node_type: string;
  asset_id: string;
  asset_name: string;
  technique_id: string;
  technique_name: string;
  cve_id?: string;
  description: string;
  risk_contribution: number;
}

export interface AttackPath {
  path_id: string;
  title: string;
  entry_point: string;
  target_crown_jewel_id: string;
  target_crown_jewel_name: string;
  accumulated_risk_score: number;
  hop_count: number;
  status: 'ACTIVE' | 'SEVERED';
  associated_choke_point_ids: string[];
  nodes: AttackPathNode[];
  severed_by_choke_point?: string;
  severed_at?: string;
}

export interface ChokePoint {
  choke_point_id: string;
  title: string;
  category: string;
  description: string;
  affected_paths_count: number;
  affected_path_ids: string[];
  target_assets: string[];
  remediation_action: string;
  disruption_efficiency_percent: number;
  is_remediated: boolean;
  remediated_at?: string;
}

export interface ChokePointRemediationResult {
  choke_point_id: string;
  title: string;
  severed_paths_count: number;
  severed_path_ids: string[];
  new_resilience_index: number;
  remediation_status: string;
  applied_at: string;
}

export interface ExposureMetrics {
  attack_path_resilience_index: number;
  total_crown_jewels: number;
  isolated_crown_jewels_count: number;
  total_attack_paths_discovered: number;
  active_attack_paths_count: number;
  severed_attack_paths_count: number;
  total_choke_points_identified: number;
  active_choke_points_count: number;
  remediated_choke_points_count: number;
  mean_attack_path_length_hops: number;
  last_evaluated_at: string;
}

export type CloudProviderType = 'AWS' | 'AZURE' | 'GCP' | 'KUBERNETES';
export type FindingSeverityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingStatusType = 'OPEN' | 'REMEDIATED' | 'SUPPRESSED';

export interface CspmPolicy {
  policy_id: string;
  title: string;
  provider: CloudProviderType;
  benchmark: string;
  section: string;
  severity: FindingSeverityType;
  description: string;
  remediation_guide: string;
}

export interface CloudFinding {
  finding_id: string;
  policy_id: string;
  title: string;
  provider: CloudProviderType;
  severity: FindingSeverityType;
  status: FindingStatusType;
  resource_id: string;
  resource_name: string;
  region: string;
  first_detected_at: string;
  description: string;
  iac_file_path: string;
  iac_format: string;
  remediated_at?: string;
  pull_request_id?: string;
}

export interface IacPatch {
  finding_id: string;
  iac_format: string;
  target_file: string;
  pull_request_branch: string;
  commit_message: string;
  unified_diff: string;
  synthesized_code: string;
}

export interface CspmRemediationResult {
  finding_id: string;
  title: string;
  status: string;
  pull_request_id: string;
  pull_request_branch: string;
  target_file: string;
  iac_format: string;
  commit_message: string;
  applied_at: string;
  new_compliance_score: number;
}

export interface CspmMetrics {
  overall_cis_compliance_percent: number;
  total_cloud_resources_scanned: number;
  total_findings_count: number;
  active_findings_count: number;
  remediated_findings_count: number;
  critical_findings_count: number;
  high_findings_count: number;
  medium_findings_count: number;
  compliance_by_provider: Record<string, number>;
  automated_remediation_rate_percent: number;
  last_scan_timestamp: string;
}

// Software Supply Chain Security (SCA) & SBOM Governance Types
export type ScaEcosystem = 'pypi' | 'npm' | 'golang' | 'cargo' | 'maven';
export type ScaSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ScaReachability = 'DIRECT_EXECUTION_PATH' | 'TRANSITIVE_CALLABLE' | 'UNREACHABLE';
export type ScaStatus = 'OPEN' | 'REMEDIATED' | 'SUPPRESSED';

export interface SbomSummary {
  sbom_id: string;
  name: string;
  version: string;
  ecosystem: string;
  format: string;
  total_components: number;
  direct_count: number;
  transitive_count: number;
  critical_vulns: number;
  high_vulns: number;
  compliance_status: string;
  created_at: string;
  serial_number: string;
}

export interface PackageComponent {
  component_id: string;
  sbom_id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  is_direct: boolean;
  license: string;
  license_risk: string;
  vulnerabilities_count: number;
  has_cisa_kev: boolean;
  top_cvss: number;
}

export interface ScaVulnerability {
  vuln_id: string;
  cve_id: string;
  component_id: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  ecosystem: string;
  severity: ScaSeverity;
  cvss_score: number;
  epss_score: number;
  cisa_kev: boolean;
  cisa_due_date?: string;
  title: string;
  description: string;
  reachability: ScaReachability;
  reachability_rationale: string;
  status: ScaStatus;
  detected_at: string;
  remediated_at?: string;
  remediation_pr?: string;
}

export interface SupplyChainThreat {
  threat_id: string;
  type: string;
  package_name: string;
  target_package: string;
  levenshtein_distance: number;
  ecosystem: string;
  severity: string;
  risk_score: number;
  detected_in: string;
  detection_reason: string;
  status: string;
  detected_at: string;
}

export interface LicenseRisk {
  risk_id: string;
  component_id: string;
  package_name: string;
  version: string;
  license: string;
  risk_level: string;
  category: string;
  commercial_impact: string;
  recommendation: string;
  status: string;
}

export interface ScaRemediationPatch {
  vuln_id: string;
  cve_id: string;
  package_name: string;
  manifest_file: string;
  git_branch: string;
  pr_title: string;
  commit_message: string;
  unified_diff: string;
}

export interface ScaRemediationResult {
  status: string;
  vuln_id: string;
  cve_id?: string;
  component_id?: string;
  package_name?: string;
  new_version?: string;
  git_pr_branch?: string;
  vulnerability_status: string;
  new_health_score: number;
  audit_trail_id: string;
  timestamp: string;
}

export interface ScaMetrics {
  health_score: number;
  total_sboms: number;
  total_components: number;
  direct_components: number;
  transitive_components: number;
  total_vulnerabilities: number;
  open_vulnerabilities: number;
  remediated_vulnerabilities: number;
  remediation_rate: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  cisa_kev_active: number;
  direct_reachable_active: number;
  active_threats_count: number;
  license_violations_count: number;
  last_scan_time: string;
}

// Master SOC Command Nexus Types
export type SubsystemOperationalStatus = 'ONLINE' | 'DEGRADED' | 'LOCKDOWN' | 'OFFLINE';

export interface SubsystemHealth {
  id: string;
  name: string;
  code: string;
  category: string;
  engine_type: string;
  status: SubsystemOperationalStatus;
  latency_ms: number;
  uptime_percent: number;
  events_per_sec: number;
  endpoint: string;
}

export interface MasterPosture {
  defense_readiness_index: number;
  platform_status: string;
  total_subsystems: number;
  online_subsystems: number;
  mean_time_to_detect_sec: number;
  mean_time_to_remediate_sec: number;
  automated_containment_rate: number;
  total_events_processed: number;
  total_threats_blocked: number;
  zero_trust_status: string;
  choke_points_severed: number;
  active_cve_mitigations: number;
  cis_cloud_compliance_percent: number;
  sbom_components_governed: number;
  is_lockdown_active: boolean;
  lockdown_details?: {
    lockdown_id: string;
    operator: string;
    reason: string;
    initiated_at: string;
    containment_actions: string[];
    quarantined_subnets: string[];
    mitre_containment_coverage: string[];
  };
  subsystems: SubsystemHealth[];
  last_evaluated_at: string;
}

export interface EmergencyLockdownResult {
  status: string;
  lockdown_id: string;
  is_lockdown_active: boolean;
  actions_executed_count: number;
  quarantined_subnets_count: number;
  readiness_index: number;
  audit_trail_id: string;
  details: any;
  timestamp: string;
}

export interface DiagnosticItem {
  subsystem_id: string;
  name: string;
  code: string;
  health: string;
  latency_ms: number;
  uptime_percent: number;
  memory_leak_check: string;
  concurrency_lock_check: string;
}

export interface PlatformDiagnostics {
  platform_certification: string;
  total_checks_passed: number;
  total_checks_failed: number;
  ai_defense_score: number;
  diagnostics_timestamp: string;
  engine_results: DiagnosticItem[];
}







