"""CIC-IDS2017 Dataset adapter, column mapper, and normalization parser.

Maps Canadian Institute for Cybersecurity flow records to CommonEventSchema.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
from ml.features.definitions import FEATURE_DEFAULTS, ATTACK_CATEGORIES

# Mapping of original CIC-IDS2017 attack labels to platform attack categories
CIC_LABEL_MAP: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "DDoS": "DOS_DDOS",
    "DoS Hulk": "DOS_DDOS",
    "DoS GoldenEye": "DOS_DDOS",
    "DoS slowloris": "DOS_DDOS",
    "DoS Slowhttptest": "DOS_DDOS",
    "PortScan": "PORT_SCAN",
    "FTP-Patator": "BRUTE_FORCE",
    "SSH-Patator": "BRUTE_FORCE",
    "Web Attack – Brute Force": "WEB_ATTACK",
    "Web Attack – XSS": "WEB_ATTACK",
    "Web Attack – Sql Injection": "WEB_ATTACK",
    "Bot": "BOTNET",
    "Infiltration": "SUSPICIOUS_AUTH",
    "Heartbleed": "ANOMALOUS_OTHER",
}


class CICIDS2017Adapter:
    """Parses and converts CIC-IDS2017 CSV flow records to platform features."""

    @staticmethod
    def map_label(raw_label: str) -> str:
        clean = str(raw_label).strip()
        for pattern, mapped in CIC_LABEL_MAP.items():
            if pattern.lower() in clean.lower():
                return mapped
        return "ANOMALOUS_OTHER"

    @classmethod
    def convert_row_to_features(cls, row: Dict[str, Any]) -> Dict[str, float]:
        """Converts a single raw CIC-IDS2017 row into standard platform features."""
        features = FEATURE_DEFAULTS.copy()

        # Handle column variations in CIC-IDS2017 files (e.g. leading spaces)
        def get_val(*col_names: str) -> Optional[float]:
            for name in col_names:
                for k, v in row.items():
                    if k.strip().lower() == name.strip().lower():
                        try:
                            val = float(v)
                            return val if pd.notnull(val) else None
                        except (ValueError, TypeError):
                            return None
            return None

        flow_dur = get_val("Flow Duration")
        if flow_dur is not None:
            features["flow_duration_ms"] = max(0.001, flow_dur / 1000.0)

        fwd_pkts = get_val("Total Fwd Packets")
        if fwd_pkts is not None:
            features["total_fwd_packets"] = fwd_pkts

        bwd_pkts = get_val("Total Backward Packets")
        if bwd_pkts is not None:
            features["total_bwd_packets"] = bwd_pkts

        fwd_bytes = get_val("Total Length of Fwd Packets")
        if fwd_bytes is not None:
            features["total_fwd_bytes"] = fwd_bytes

        bwd_bytes = get_val("Total Length of Bwd Packets")
        if bwd_bytes is not None:
            features["total_bwd_bytes"] = bwd_bytes

        dst_port = get_val("Destination Port")
        if dst_port is not None:
            features["destination_port"] = dst_port

        flow_bytes_s = get_val("Flow Bytes/s")
        if flow_bytes_s is not None:
            features["flow_bytes_per_sec"] = max(0.0, flow_bytes_s)

        flow_pkts_s = get_val("Flow Packets/s")
        if flow_pkts_s is not None:
            features["flow_packets_per_sec"] = max(0.0, flow_pkts_s)

        # Derived ratios
        tot_bytes = features["total_fwd_bytes"] + features["total_bwd_bytes"]
        features["bytes_out_ratio"] = features["total_fwd_bytes"] / max(1.0, tot_bytes)

        return features

    @classmethod
    def parse_dataframe(cls, df: pd.DataFrame, max_rows: Optional[int] = None) -> pd.DataFrame:
        """Transforms a CIC-IDS2017 DataFrame into platform feature DataFrame."""
        sample = df.head(max_rows) if max_rows else df
        records: List[Dict[str, Any]] = []

        label_col = next((c for c in sample.columns if "label" in c.lower()), None)

        for _, row in sample.iterrows():
            row_dict = row.to_dict()
            feat = cls.convert_row_to_features(row_dict)
            raw_label = row_dict.get(label_col, "BENIGN") if label_col else "BENIGN"
            feat["attack_category"] = cls.map_label(str(raw_label))
            records.append(feat)

        return pd.DataFrame(records)

