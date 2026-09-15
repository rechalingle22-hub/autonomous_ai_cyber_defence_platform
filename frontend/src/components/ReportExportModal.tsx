import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Incident, SecurityReport, ReportType, ReportFormat } from '../types';

interface ReportExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  incidents: Incident[];
  selectedIncidentId?: string;
}

export const ReportExportModal: React.FC<ReportExportModalProps> = ({
  isOpen,
  onClose,
  incidents,
  selectedIncidentId,
}) => {
  const [reportType, setReportType] = useState<ReportType>('EXECUTIVE_SUMMARY');
  const [format, setFormat] = useState<ReportFormat>('HTML');
  const [incidentId, setIncidentId] = useState<string>(selectedIncidentId || '');
  const [customTitle, setCustomTitle] = useState<string>('');
  const [generating, setGenerating] = useState<boolean>(false);
  const [recentReports, setRecentReports] = useState<SecurityReport[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (selectedIncidentId) {
      setIncidentId(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const loadRecentReports = async () => {
    try {
      const reports = await api.getReports();
      setRecentReports(reports);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadRecentReports();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleGenerate = async () => {
    setGenerating(true);
    setErrorMsg(null);
    try {
      const report = await api.generateReport({
        incident_id: incidentId ? incidentId : undefined,
        report_type: reportType,
        format: format,
        title: customTitle.trim() ? customTitle.trim() : undefined,
      });

      // Trigger automatic browser download
      const downloadUrl = api.getReportDownloadUrl(report.id);
      window.open(downloadUrl, '_blank');

      await loadRecentReports();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl max-w-2xl w-full p-6 shadow-2xl relative text-slate-100">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-sky-500/20 border border-sky-500/40 flex items-center justify-center text-sky-400">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-wide">Security Report & Dossier Generator</h3>
              <p className="text-xs text-slate-400">Generate executive CISO briefs, forensic dossiers, or compliance audits</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-slate-800 transition"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {errorMsg && (
          <div className="mt-4 p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-xs text-red-300">
            {errorMsg}
          </div>
        )}

        <div className="mt-5 space-y-4">
          {/* Target Incident Selection */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Target Scope / Incident
            </label>
            <select
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="">Platform-Wide Cyber Defense Posture (All Incidents)</option>
              {incidents.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  [{inc.severity}] {inc.title} ({inc.id.slice(0, 8)}...)
                </option>
              ))}
            </select>
          </div>

          {/* Report Type */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Report Type
              </label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
              >
                <option value="EXECUTIVE_SUMMARY">Executive CISO Summary</option>
                <option value="TECHNICAL_FORENSIC_DOSSIER">Technical Forensic Dossier</option>
                <option value="INCIDENT_POST_MORTEM">Incident Post-Mortem (RCA)</option>
                <option value="COMPLIANCE_AUDIT">Compliance Audit (NIST / ISO)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Serialization Format
              </label>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as ReportFormat)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
              >
                <option value="HTML">HTML (Print-to-PDF Ready)</option>
                <option value="MARKDOWN">Markdown (.md GFM)</option>
                <option value="JSON">Structured JSON (SIEM/STIX)</option>
                <option value="CSV">Tabular CSV (Spreadsheet)</option>
              </select>
            </div>
          </div>

          {/* Custom Title */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Custom Title (Optional)
            </label>
            <input
              type="text"
              placeholder="e.g. Q3 Executive Threat Briefing or Incident INC-942 Dossier"
              value={customTitle}
              onChange={(e) => setCustomTitle(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="pt-2">
            <button
              onClick={handleGenerate}
              disabled={generating}
              className="w-full bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold py-2.5 px-4 rounded-lg flex items-center justify-center gap-2 transition shadow-lg shadow-sky-600/20"
            >
              {generating ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                  <span>Synthesizing Report Artifact...</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  <span>Generate &amp; Download Report</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Recently Generated Reports */}
        {recentReports.length > 0 && (
          <div className="mt-6 pt-5 border-t border-slate-800">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
              Recently Archived Reports ({recentReports.length})
            </h4>
            <div className="max-h-40 overflow-y-auto space-y-2 pr-1 text-xs">
              {recentReports.slice(0, 5).map((r) => (
                <div
                  key={r.id}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-slate-700 transition"
                >
                  <div className="truncate pr-2">
                    <div className="font-semibold text-slate-200 truncate">{r.title}</div>
                    <div className="text-[11px] text-slate-500 flex gap-2 mt-0.5">
                      <span className="text-sky-400 font-mono">{r.format}</span>
                      <span>&bull;</span>
                      <span>{(r.file_size_bytes / 1024).toFixed(1)} KB</span>
                      <span>&bull;</span>
                      <span>{new Date(r.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                  <a
                    href={api.getReportDownloadUrl(r.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-400 hover:text-sky-300 font-semibold rounded text-[11px] flex items-center gap-1 transition"
                  >
                    Download
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

