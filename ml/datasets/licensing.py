"""Academic citations, licensing specifications, and ethical use guidelines for public datasets.

References:
- CIC-IDS2017 & CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity)
- UNSW-NB15 (Cyber Range Lab of the Australian Centre for Cyber Security)
"""

from typing import Dict, Any

DATASET_CATALOG: Dict[str, Dict[str, Any]] = {
    "CIC-IDS2017": {
        "title": "CIC-IDS2017 Dataset",
        "institution": "Canadian Institute for Cybersecurity (CIC), University of New Brunswick",
        "authors": "Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani",
        "citation": (
            "Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). "
            "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. "
            "Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 108-116."
        ),
        "license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
        "intended_use": "Academic and defensive cybersecurity research only; non-commercial benchmarking.",
        "attack_types": [
            "DoS", "DDoS", "PortScan", "Brute Force (SSH/FTP)",
            "Web Attacks (Sql Injection, XSS)", "Botnet", "Infiltration"
        ],
        "ethical_declaration": (
            "This platform processes sanitized network flow extracts strictly for defensive anomaly detection "
            "and signature training in isolated lab environments."
        ),
    },
    "UNSW-NB15": {
        "title": "UNSW-NB15 Dataset",
        "institution": "Cyber Range Lab of the Australian Centre for Cyber Security (ACCS), UNSW Canberra",
        "authors": "Nour Moustafa, Jill Slay",
        "citation": (
            "Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion "
            "detection systems (UNSW-NB15 network data set). Military Communications and Information Systems "
            "Conference (MilCIS), 1-6."
        ),
        "license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
        "intended_use": "Defensive intrusion detection research and evaluation of network traffic anomaly detection.",
        "attack_types": [
            "Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits",
            "Generic", "Reconnaissance", "Shellcode", "Worms"
        ],
        "ethical_declaration": (
            "Evaluated strictly in simulated environments using pre-extracted PCAP features without executing "
            "exploits on external networks."
        ),
    },
    "CSE-CIC-IDS2018": {
        "title": "CSE-CIC-IDS2018 Dataset",
        "institution": "Communications Security Establishment (CSE) & Canadian Institute for Cybersecurity (CIC)",
        "authors": "Canadian Institute for Cybersecurity",
        "citation": (
            "Canadian Institute for Cybersecurity (2018). A realistic cyber defense dataset (CSE-CIC-IDS2018). "
            "University of New Brunswick."
        ),
        "license": "Open Data Commons Open Database License (ODbL) / Research Use",
        "intended_use": "Systematic evaluation of intrusion detection machine learning models.",
        "attack_types": [
            "Brute Force", "Heartbleed", "Botnet", "DoS", "DDoS", "Web Attacks", "Infiltration"
        ],
        "ethical_declaration": (
            "Network flows used solely to benchmark detection accuracy and evaluate model drift."
        ),
    },
}


def get_dataset_metadata(dataset_name: str) -> Dict[str, Any]:
    """Returns license and attribution metadata for the requested dataset."""
    name_upper = dataset_name.upper()
    for key, val in DATASET_CATALOG.items():
        if key.upper() == name_upper:
            return val
    raise ValueError(f"Unknown dataset: {dataset_name}. Supported: {list(DATASET_CATALOG.keys())}")

