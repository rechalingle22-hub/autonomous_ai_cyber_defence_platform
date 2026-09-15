import React, { useState } from 'react';
import { api } from '../services/api';
import { XaiExplanation, XaiFactor } from '../types';
import { Cpu, CheckCircle2, TrendingUp, TrendingDown, Play } from 'lucide-react';

export const XaiInspectorView: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<string>('BRUTE_FORCE');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    attack_type: string;
    confidence: number;
    severity: string;
    xai_explanation: XaiExplanation;
  } | null>(null);

  const presets: Record<string, any> = {
    BRUTE_FORCE: {
      source_ip: '192.168.1.105',
      destination_ip: '10.0.0.5',
      source_port: 49152,
      destination_port: 22,
      protocol: 'TCP',
      features: {
        flow_duration_ms: 120.0,
        total_fwd_packets: 8.0,
        total_bwd_packets: 6.0,
        failed_logins_window: 42.0,
        destination_port: 22.0,
        flow_bytes_per_sec: 7500.0,
        port_entropy: 0.05,
        bytes_out_ratio: 0.5,
      },
    },
    EXFILTRATION: {
      source_ip: '10.0.0.12',
      destination_ip: '198.51.100.88',
      source_port: 54321,
      destination_port: 443,
      protocol: 'TCP',
      features: {
        flow_duration_ms: 85000.0,
        total_fwd_packets: 520.0,
        total_bwd_packets: 30.0,
        total_fwd_bytes: 4500000.0,
        total_bwd_bytes: 2500.0,
        bytes_out_ratio: 0.98,
        destination_port: 443.0,
        failed_logins_window: 0.0,
        flow_bytes_per_sec: 53000.0,
      },
    },
    PORT_SCAN: {
      source_ip: '203.0.113.15',
      destination_ip: '10.0.0.1',
      source_port: 38291,
      destination_port: 80,
      protocol: 'TCP',
      features: {
        flow_duration_ms: 15.0,
        total_fwd_packets: 1.0,
        total_bwd_packets: 0.0,
        port_entropy: 3.85,
        destination_port: 80.0,
        bytes_out_ratio: 1.0,
        failed_logins_window: 0.0,
      },
    },
  };

  const handleRunInference = async (presetKey: string) => {
    setSelectedPreset(presetKey);
    setLoading(true);
    try {
      const payload = presets[presetKey];
      const data = await api.classifyFlow(payload);
      setResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Preset Selector Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-mono font-bold text-slate-100 flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>TreeSHAP Local Explainability Analyzer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Evaluates cooperative game-theoretic Shapley value attributions for individual network flow detections.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {Object.keys(presets).map((key) => (
            <button
              key={key}
              onClick={() => handleRunInference(key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition border ${
                selectedPreset === key
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm'
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
              }`}
            >
              Preset: {key}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="p-16 rounded-xl bg-slate-900/60 border border-slate-800 text-center font-mono text-xs text-slate-400">
          Calculating TreeSHAP Shapley feature attributions...
        </div>
      ) : result ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Prediction Overview Card */}
          <div className="lg:col-span-4 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              Ensemble Model Classification
            </div>

            <div className="p-4 rounded-xl bg-slate-800/60 border border-slate-700/60">
              <div className="text-xs font-mono text-slate-400">PREDICTED ATTACK CATEGORY</div>
              <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
                {result.attack_type}
              </div>
              <div className="flex items-center justify-between text-xs font-mono text-slate-300 mt-3 pt-3 border-t border-slate-700/60">
                <span>CONFIDENCE:</span>
                <span className="text-cyan-400 font-bold">
                  {(result.confidence * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex items-center justify-between text-xs font-mono text-slate-300 mt-1">
                <span>SEVERITY:</span>
                <span className="text-rose-400 font-bold">{result.severity}</span>
              </div>
              <div className="flex items-center justify-between text-xs font-mono text-slate-300 mt-1">
                <span>METHOD:</span>
                <span className="text-slate-400">TreeSHAP (Exact)</span>
              </div>
            </div>

            {/* Plain English Summary */}
            <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-xs font-mono text-cyan-300 leading-relaxed">
              <div className="font-bold text-cyan-400 mb-1 flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Deterministic Summary</span>
              </div>
              {result.xai_explanation.deterministic_summary}
            </div>
          </div>

          {/* Feature Attribution Waterfall */}
          <div className="lg:col-span-8 p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
              <span>Top Contributing Risk Drivers (&Phi; Attributions)</span>
              <span className="text-[11px] text-slate-500 lowercase">higher value = higher risk</span>
            </div>

            <div className="space-y-3">
              {result.xai_explanation.contributing_factors.map((factor: XaiFactor) => {
                const isRisk = factor.impact === 'INCREASED_RISK';
                const magnitude = Math.min(100, Math.abs(factor.shap_attribution) * 20);

                return (
                  <div
                    key={factor.feature}
                    className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs font-mono space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-slate-400 font-bold">#{factor.rank}</span>
                        <span className="text-slate-100 font-semibold">{factor.feature}</span>
                        <span className="text-slate-400 text-[11px]">
                          (val: {factor.raw_value})
                        </span>
                      </div>

                      <div
                        className={`flex items-center space-x-1 font-bold ${
                          isRisk ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                      >
                        {isRisk ? (
                          <TrendingUp className="w-3.5 h-3.5" />
                        ) : (
                          <TrendingDown className="w-3.5 h-3.5" />
                        )}
                        <span>
                          {factor.shap_attribution > 0 ? '+' : ''}
                          {factor.shap_attribution.toFixed(3)}
                        </span>
                      </div>
                    </div>

                    <div className="text-slate-400 text-[11px]">{factor.description}</div>

                    {/* Attribution bar */}
                    <div className="w-full bg-slate-700/50 rounded-full h-1.5 overflow-hidden mt-2">
                      <div
                        className={`h-full rounded-full ${
                          isRisk ? 'bg-rose-500' : 'bg-emerald-500'
                        }`}
                        style={{ width: `${Math.max(5, magnitude)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-16 rounded-xl bg-slate-900/60 border border-slate-800 text-center font-mono text-xs text-slate-400">
          Click any preset button above to run TreeSHAP feature attribution inference.
        </div>
      )}
    </div>
  );
};

