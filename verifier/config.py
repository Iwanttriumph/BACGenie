from __future__ import annotations

from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
ROOT_DIR = SRC_DIR.parent
PROMPTS_DIR = SRC_DIR / "prompts"
SCHEMAS_DIR = SRC_DIR / "schemas"

# Default LLM configuration
DEFAULT_MODEL = "deepseek-v4.1-flash"
DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"

# Default local & remote deliverables locations inside unified BACGenie repo
DEFAULT_SSH_HOST = "ddk@10.176.46.12"
DEFAULT_LOCAL_DELIVERABLES = ROOT_DIR / "deliverables" / "BACGenie"
DEFAULT_REMOTE_DELIVERABLES = "/hdd1/congxy/AAPaper/NewIdea/BACGenie/deliverables/BACGenie"
DEFAULT_BENCHMARK_FILE = ROOT_DIR / "experiment" / "benchmark_23.json"
DEFAULT_RESULTS_DIR = ROOT_DIR / "verifier_results"

# Source retrieval limits for the Agent Auditor
MAX_TOOL_ROUNDS = 8
MAX_OPS_PER_ROUND = 5
MAX_READ_LINES = 200
MAX_SOURCE_CHARS = 80_000

# Sampling configuration for 'True' verdicts ("大多数，需人工抽样核验")
DEFAULT_SAMPLE_RATE = 0.30
MIN_TRUE_SAMPLES = 3
DEFAULT_SAMPLE_SEED = 20261126

VERIFIER_VERSION = "1.0.0"
