"""UNSW-NB15 Dataset adapter, column mapper, and normalization parser.

Maps Australian Centre for Cyber Security UNSW-NB15 flow records to CommonEventSchema.
"""

from typing import Dict, Any, List, Optional
import pandas as pd
from ml.features.definitions import FEATURE_DEFAULTS

# Mapping of original UNSW-NB15 attack categories to platform attack taxonomy
UNSW_LABEL_MAP: Dict[str, str] = {
    "normal": "BENIGN",
    "fuzzers": "ANOMALOUS_OTHER",
    "analysis": "PORT_SCAN",
    "backdoors": "BOTNET",
    "backdoor": "BOTNET",
    "dos": "DOS_DDOS",
    "exploits": "WEB_ATTACK",
    "generic": "ANOMALOUS_OTHER",
    "reconnaissance": "PORT_SCAN",
    "shellcode": "WEB_ATTACK",
    "worms": "BOTNET",
}


class UNSWNB15Adapter:
    """Parses and converts UNSW-NB15 CSV records to platform standard features."""

    @staticmethod
    def map_label(raw_label: str) -> str:
        clean = str(raw_label).strip().lower()
        if not clean or clean in ["0", "benign"]:
            return "BENIGN"
        for pattern, mapped in UNSW_LABEL_MAP.items():
            if pattern in clean:
                return mapped
        return "ANOMALOUS_OTHER"

    @classmethod
    def convert_row_to_features(cls, row: Dict[str, Any]) -> Dict[str, float]:
        """Converts a single raw UNSW-NB15 record into standard platform features."""
        features = FEATURE_DEFAULTS.copy()

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

        dur = get_val("dur")
        if dur is not None:
            features["flow_duration_ms"] = max(0.001, dur * 1000.0)

        spkts = get_val("spkts")
        if spkts is not None:
            features["total_fwd_packets"] = spkts

        dpkts = get_val("dpkts")
        if dpkts is not None:
            features["total_bwd_packets"] = dpkts

        sbytes = get_val("sbytes")
        if sbytes is not None:
            features["total_fwd_bytes"] = sbytes

        dbytes = get_val("dbytes")
        if dbytes is not None:
            features["total_bwd_bytes"] = dbytes

        tot_bytes = features["total_fwd_bytes"] + features["total_bwd_bytes"]
        features["bytes_out_ratio"] = features["total_fwd_bytes"] / max(1.0, tot_bytes)

        sload = get_val("sload")
        dload = get_val("dload")
        if sload is not None and dload is not None:
            features["flow_bytes_per_sec"] = max(0.0, (sload + dload) / 8.0)

        return features

    @classmethod
    def parse_dataframe(cls, df: pd.DataFrame, max_rows: Optional[int] = None) -> pd.DataFrame:
        """Transforms a UNSW-NB15 DataFrame into platform feature DataFrame."""
        sample = df.head(max_rows) if max_rows else df
        records: List[Dict[str, Any]] = []

        attack_cat_col = next((c for c in sample.columns if "attack_cat" in c.lower()), None)
        label_col = next((c for c in sample.columns if c.strip().lower() == "label"), None)

        for _, row in sample.iterrows():
            row_dict = row.to_dict()
            feat = cls.convert_row_to_features(row_dict)

            # Determine label: if binary label is 0, it's BENIGN, otherwise check attack_cat
            is_attack = row_dict.get(label_col, 0) if label_col else 0
            if str(is_attack).strip() == "0":
                feat["attack_category"] = "BENIGN"
            else:
                cat = row_dict.get(attack_cat_col, "generic") if attack_cat_col else "generic"
                feat["attack_category"] = cls.map_label(str(cat))

            records.append(feat)

        return pd.DataFrame(records)

