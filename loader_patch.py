"""
Cross-platform path handling for Piranha data files (Linux/Windows safe).

- Uses pathlib everywhere (no backslashes).
- Allows environment variable overrides for all important paths.
- Falls back to sensible defaults under /opt/piranha/backend/files, etc.
"""

from pathlib import Path
import os
import json
from functools import lru_cache
from backend.logging_config import logger

# ---------- path helpers ----------

def _norm_path(p: str | Path) -> Path:
    """
    Normalize any accidental Windows-style backslashes to POSIX,
    then return a resolved Path (non-strict).
    """
    if isinstance(p, Path):
        return p.resolve()
    return Path(str(p).replace("\\", "/")).resolve()

def _env_path(key: str, default: Path) -> Path:
    v = os.environ.get(key)
    return _norm_path(v) if v else _norm_path(default)

# ---------- base locations (import-time) ----------

# /opt/piranha/backend
BASE_DIR = Path(__file__).resolve().parent

# Defaults under backend/files
FILES_DIR             = _env_path("PIRANHA_FILES_DIR", BASE_DIR / "files")
APT_JSON_DIR          = _env_path("PIRANHA_APT_DIR", FILES_DIR / "APT")
CVE_TO_TCODE_DIR      = _env_path("PIRANHA_CVE_DB", BASE_DIR.parent / "CVE2CAPEC" / "database")
KEYWORD_IOC_FILE      = _env_path("PIRANHA_KEYWORD_IOC", FILES_DIR / "KEYWORD_IOC_MAPPING.json")
DATA_COMPONENTS_FILE  = _env_path("PIRANHA_DATA_COMPONENTS", FILES_DIR / "DATA_COMPONENTS_MAPPING.json")

# Explicit MITRE JSONs (overrides optional)
MITRE_ENTERPRISE_JSON = _env_path("MITRE_ENTERPRISE_JSON", FILES_DIR / "enterprise-attack.json")
MITRE_MOBILE_JSON     = _env_path("MITRE_MOBILE_JSON",     FILES_DIR / "mobile-attack.json")
MITRE_ICS_JSON        = _env_path("MITRE_ICS_JSON",        FILES_DIR / "ics-attack.json")

# ---------- loaders ----------

def load_component_json():
    if DATA_COMPONENTS_FILE.exists():
        try:
            with DATA_COMPONENTS_FILE.open("r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"JSON Error in {DATA_COMPONENTS_FILE}: {e}")
    logger.warning(f"No JSON file found for {DATA_COMPONENTS_FILE}. Returning empty dict.")
    return {}

def load_apt_json(apt_name, selected_datasets):
    """
    Load APT JSON by name, honoring MOBILE/ICS variants when requested.
    """
    variants = [apt_name]
    if selected_datasets.get("mobile"):
        variants.append(f"{apt_name}-MOBILE")
    if selected_datasets.get("ics"):
        variants.append(f"{apt_name}-ICS")

    for variant in variants:
        apt_file = APT_JSON_DIR / f"{variant}.json"
        if apt_file.exists():
            try:
                with apt_file.open("r", encoding="utf-8") as f:
                    logger.info(f"Loaded APT JSON: {apt_file}")
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"JSON Error in {apt_file}: {e}")

    logger.warning(f"No JSON file found for {apt_name} across selected datasets. Using global IOC mapping.")
    return {}

def load_keyword_ioc_mapping():
    if KEYWORD_IOC_FILE.exists():
        try:
            with KEYWORD_IOC_FILE.open("r", encoding="utf-8") as f:
                data = json.load(f)
                # Normalize fields
                for key, value in data.items():
                    if isinstance(value.get("ioc"), str):
                        value["ioc"] = [value["ioc"]]
                    if isinstance(value.get("tools"), list):
                        value["tools"] = set(value["tools"])  # internal use; deduplicate
                return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON Error in {KEYWORD_IOC_FILE}: {e}")
    logger.warning("No valid keyword-to-IOC mapping found. Using empty dictionary.")
    return {}

@lru_cache(maxsize=None)
def load_mitre_data_cached(enterprise=True, mobile=False, ics=False):
    return load_mitre_data({"enterprise": enterprise, "mobile": mobile, "ics": ics})

def load_mitre_data(selected_datasets):
    """
    Merge selected ATT&CK datasets into one dict and build a T-code -> dataset map.
    Returns: (combined_data_or_None, tcode_dataset_mapping)
    """
    dataset_files = {
        "enterprise": MITRE_ENTERPRISE_JSON,
        "mobile":     MITRE_MOBILE_JSON,
        "ics":        MITRE_ICS_JSON,
    }

    combined = {"objects": []}
    dataset_mapping = {}

    for dataset, selected in selected_datasets.items():
        if not selected:
            continue
        json_path = dataset_files[dataset]
        if json_path.exists():
            logger.info(f"Loading {json_path}")
            try:
                with json_path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
            except json.JSONDecodeError as e:
                logger.error(f"JSON Error in {json_path}: {e}")
                continue

            for obj in data.get("objects", []):
                combined["objects"].append(obj)
                if obj.get("type") == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        ext_id = ref.get("external_id")
                        if ext_id and ext_id.startswith("T"):
                            dataset_mapping[ext_id] = dataset
                            break
        else:
            logger.error(f"{json_path} not found!")

    return (combined if combined["objects"] else None, dataset_mapping)

# ---------- CVE → Technique mapping ----------

loaded_cve_data = {}

def extract_year_from_cve(cve: str):
    """Extract the year from a CVE ID (e.g., 'CVE-2023-1234' -> '2023')."""
    try:
        return cve.split("-")[1]
    except Exception:
        return None

def load_cve_mappings(year: str):
    """Load CVE-to-TCode mappings for a given year from JSONL."""
    file_path = CVE_TO_TCODE_DIR / f"cve-{year}.jsonl"
    if not file_path.exists():
        logger.warning(f"CVE data file {file_path} not found.")
        return {}

    cve_data = {}
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                cve_id = next(iter(entry.keys()))
                cve_data[cve_id] = entry[cve_id]
            except Exception:
                logger.error(f"Failed to parse line in {file_path}")
    logger.info(f"Loaded {len(cve_data)} CVEs from {file_path}")
    return cve_data

def load_tcodes_for_cve(cve: str):
    """Return list of technique codes for a given CVE from cached JSONL datasets."""
    year = extract_year_from_cve(cve)
    if not year:
        logger.warning(f"Could not extract year from {cve}")
        return []

    if year not in loaded_cve_data:
        loaded_cve_data[year] = load_cve_mappings(year)

    entry = loaded_cve_data[year].get(cve, {})
    t_codes = entry.get("TECHNIQUES", [])

    if isinstance(t_codes, str):
        t_codes = [t_codes]
    elif not isinstance(t_codes, list):
        t_codes = []

    return [str(t).strip() for t in t_codes]
