# File: audit_logger.py
import json
import logging
from datetime import datetime
from pathlib import Path

# =====================================================
# Configuration
# =====================================================
AUDIT_FILE = Path("audit_log.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("audit_logger")

# =====================================================
# JSON Audit Utilities
# =====================================================

def _load_audit_file():
    """Load existing audit entries."""
    if AUDIT_FILE.exists():
        try:
            with open(AUDIT_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("⚠️ Corrupted audit log, starting new.")
    return []


def _save_audit_file(data):
    """Write full audit log back to disk."""
    with open(AUDIT_FILE, "w") as f:
        json.dump(data, f, indent=2)


def append_audit_entry(entry: dict):
    """
    Append structured audit entry to the global audit log.
    Each entry should contain:
      - timestamp
      - step (optional)
      - status
      - data / output
      - error (if applicable)
    """
    try:
        data = _load_audit_file()
        data.append(entry)
        _save_audit_file(data)
    except Exception as e:
        logger.error(f"❌ Failed to write audit entry: {e}")


def log_step(step_name: str, status: str, data=None, error=None):
    """
    Unified way to log both console + JSON audit.
    """
    timestamp = datetime.now().isoformat()
    entry = {
        "timestamp": timestamp,
        "step": step_name,
        "status": status,
        "data": data,
    }
    if error:
        entry["error"] = str(error)

    append_audit_entry(entry)

    # Console logging too
    if status == "success":
        logger.info(f"✅ [{step_name}] completed successfully.")
    elif status == "in_progress":
        logger.info(f"⏳ [{step_name}] started...")
    else:
        logger.error(f"❌ [{step_name}] failed: {error}")
