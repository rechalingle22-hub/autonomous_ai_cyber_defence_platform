"""Unit tests for benchmark dataset adapters and licensing metadata."""

import pandas as pd
import pytest
from ml.datasets.licensing import get_dataset_metadata, DATASET_CATALOG
from ml.datasets.cic_ids2017 import CICIDS2017Adapter
from ml.datasets.unsw_nb15 import UNSWNB15Adapter


def test_dataset_licensing_catalog():
    """Verifies that all three benchmark datasets have valid citation and license metadata."""
    for name in ["CIC-IDS2017", "UNSW-NB15", "CSE-CIC-IDS2018"]:
        meta = get_dataset_metadata(name)
        assert "license" in meta
        assert "citation" in meta
        assert "ethical_declaration" in meta

    with pytest.raises(ValueError):
        get_dataset_metadata("UNKNOWN_DATASET")


def test_cic_ids2017_adapter():
    """Tests converting sample raw CIC-IDS2017 CSV format records."""
    raw_records = pd.DataFrame([
        {
            " Destination Port": 80,
            " Flow Duration": 1200000,
            " Total Fwd Packets": 10,
            " Total Backward Packets": 8,
            "Total Length of Fwd Packets": 500,
            " Total Length of Bwd Packets": 4000,
            " Flow Bytes/s": 3750.0,
            " Flow Packets/s": 15.0,
            " Label": "DoS Hulk",
        },
        {
            " Destination Port": 22,
            " Flow Duration": 50000,
            " Total Fwd Packets": 2,
            " Total Backward Packets": 1,
            "Total Length of Fwd Packets": 100,
            " Total Length of Bwd Packets": 50,
            " Flow Bytes/s": 3000.0,
            " Flow Packets/s": 60.0,
            " Label": "PortScan",
        },
        {
            " Destination Port": 443,
            " Flow Duration": 80000,
            " Total Fwd Packets": 5,
            " Total Backward Packets": 5,
            "Total Length of Fwd Packets": 400,
            " Total Length of Bwd Packets": 1200,
            " Flow Bytes/s": 20000.0,
            " Flow Packets/s": 125.0,
            " Label": "BENIGN",
        },
    ])

    parsed = CICIDS2017Adapter.parse_dataframe(raw_records)
    assert len(parsed) == 3
    assert parsed.loc[0, "attack_category"] == "DOS_DDOS"
    assert parsed.loc[1, "attack_category"] == "PORT_SCAN"
    assert parsed.loc[2, "attack_category"] == "BENIGN"
    assert parsed.loc[0, "flow_duration_ms"] == 1200.0


def test_unsw_nb15_adapter():
    """Tests converting sample raw UNSW-NB15 records."""
    raw_records = pd.DataFrame([
        {
            "dur": 0.05,
            "spkts": 4,
            "dpkts": 4,
            "sbytes": 350,
            "dbytes": 500,
            "sload": 56000.0,
            "dload": 80000.0,
            "attack_cat": "Reconnaissance",
            "label": 1,
        },
        {
            "dur": 0.01,
            "spkts": 2,
            "dpkts": 2,
            "sbytes": 120,
            "dbytes": 120,
            "sload": 96000.0,
            "dload": 96000.0,
            "attack_cat": None,
            "label": 0,
        },
    ])

    parsed = UNSWNB15Adapter.parse_dataframe(raw_records)
    assert len(parsed) == 2
    assert parsed.loc[0, "attack_category"] == "PORT_SCAN"
    assert parsed.loc[1, "attack_category"] == "BENIGN"
    assert parsed.loc[0, "flow_duration_ms"] == 50.0

