#!/usr/bin/env bash
# BACGenie Single-CVE Launcher (Isolated OpenCode Runtime + Non-TTY Safe Execution)
# Usage:
#   ./bacgenie_run.sh <CVE-ID> [model] [extra_instruction]
# Example:
#   ./bacgenie_run.sh CVE-2024-11300 yeowl/deepseek-v4.1-flash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
if [[ ! -d "$PROJECT_ROOT/.opencode-runtime" && -d "$SCRIPT_DIR/../.opencode-runtime" ]]; then
  PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
RT_DIR="$PROJECT_ROOT/.opencode-runtime"
OPENCODE_BIN="${OPENCODE_BIN:-$HOME/.opencode/bin/opencode}"

if ! command -v "$OPENCODE_BIN" >/dev/null 2>&1; then
  if command -v opencode >/dev/null 2>&1; then
    OPENCODE_BIN="$(command -v opencode)"
  else
    echo "Error: opencode binary not found at $OPENCODE_BIN or PATH" >&2
    exit 1
  fi
fi

CVE_ID="${1:-}"
if [[ -z "$CVE_ID" ]]; then
  echo "Usage: $0 <CVE-ID> [model] [extra_instruction]" >&2
  exit 1
fi

MODEL="${2:-${BACGENIE_MODEL:-yeowl/deepseek-v4.1-flash}}"
EXTRA_MSG="${3:-}"

mkdir -p "$RT_DIR/config/opencode" "$RT_DIR/data" "$RT_DIR/state" "$RT_DIR/cache/opencode/bin" "$RT_DIR/tmp"
chmod 700 "$RT_DIR"

# Bootstrap offline caches from user home if available
if [[ -f "$HOME/.cache/opencode/models.json" && ! -f "$RT_DIR/cache/opencode/models.json" ]]; then
  cp -f "$HOME/.cache/opencode/models.json" "$RT_DIR/cache/opencode/models.json"
fi
if [[ -x "$HOME/.cache/opencode/bin/rg" && ! -x "$RT_DIR/cache/opencode/bin/rg" ]]; then
  cp -f "$HOME/.cache/opencode/bin/rg" "$RT_DIR/cache/opencode/bin/rg"
  chmod +x "$RT_DIR/cache/opencode/bin/rg"
fi
export PATH="$HOME/.cache/opencode/bin:$PATH"
if [[ -f "$HOME/.config/opencode/package.json" && ! -f "$RT_DIR/config/opencode/package.json" ]]; then
  cp -f "$HOME/.config/opencode/package.json" "$RT_DIR/config/opencode/package.json"
fi
if [[ -d "$HOME/.config/opencode/node_modules" && ! -e "$RT_DIR/config/opencode/node_modules" ]]; then
  ln -s "$HOME/.config/opencode/node_modules" "$RT_DIR/config/opencode/node_modules"
fi

CONFIG_FILE="$RT_DIR/config/opencode/opencode.json"
API_KEY_VAL="${BACGENIE_API_KEY:-}"
if [[ ! -f "$CONFIG_FILE" ]]; then
  if [[ -z "$API_KEY_VAL" ]]; then
    echo "Error: $CONFIG_FILE not initialized and BACGENIE_API_KEY env var is not set." >&2
    exit 1
  fi
  BASE_URL="${BACGENIE_BASE_URL:-https://yeowl.me/v1}"
  cat > "$CONFIG_FILE" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "shell": "bash",
  "permission": {
    "*": "allow",
    "bash": "allow",
    "edit": "allow",
    "external_directory": "allow"
  },
  "providers": {
    "yeowl": {
      "name": "yeowl",
      "package": "aisdk:@ai-sdk/openai-compatible",
      "settings": {
        "apiKey": "${API_KEY_VAL}",
        "baseURL": "${BASE_URL}"
      },
      "models": {
        "deepseek-v4.1-flash": {
          "modelID": "deepseek-v4.1-flash",
          "name": "DeepSeek v4.1 Flash",
          "capabilities": { "tools": true, "input": ["text"], "output": ["text"] },
          "limit": { "context": 256000, "output": 64000 }
        },
        "deepseek-v4.1-flash-1017": {
          "modelID": "deepseek-v4.1-flash-1017",
          "name": "DeepSeek v4.1 Flash 1017",
          "capabilities": { "tools": true, "input": ["text"], "output": ["text"] },
          "limit": { "context": 256000, "output": 64000 }
        },
        "glm-5.3": {
          "modelID": "glm-5.3",
          "name": "GLM 5.3",
          "capabilities": { "tools": true, "input": ["text"], "output": ["text"] },
          "limit": { "context": 200000, "output": 64000 }
        },
        "kimi-k3": {
          "modelID": "kimi-k3",
          "name": "Kimi K3",
          "capabilities": { "tools": true, "input": ["text"], "output": ["text"] },
          "limit": { "context": 256000, "output": 64000 }
        },
        "qwen3.8-max": {
          "modelID": "qwen3.8-max",
          "name": "Qwen 3.8 Max",
          "capabilities": { "tools": true, "input": ["text"], "output": ["text"] },
          "limit": { "context": 256000, "output": 64000 }
        }
      }
    }
  }
}
EOF
  chmod 600 "$CONFIG_FILE"
fi

export XDG_CONFIG_HOME="$RT_DIR/config"
export XDG_DATA_HOME="$RT_DIR/data"
export XDG_STATE_HOME="$RT_DIR/state"
export XDG_CACHE_HOME="$RT_DIR/cache"
export TMPDIR="$RT_DIR/tmp"
export OPENCODE_DISABLE_AUTOUPDATE=true
export OPENCODE_DISABLE_MODELS_FETCH=true

cd "$SCRIPT_DIR"

PROMPT="目标漏洞：${CVE_ID}。请按 BACGenie 主审架构师规范，完成源码锚定与 Oracle 契约制定（01_tp.json / 02_oracle_contract.json）、隔离靶场与 Solution 2 前置状态准备、Clean-Room 盲态脚本开发、调用 python3 harness/gate.py run runs/${CVE_ID} 完成双盲动态信标终审，并签发 runs/${CVE_ID}/reproduction_report.md。${EXTRA_MSG}"

"$OPENCODE_BIN" run --standalone --auto \
  --title "BACGenie-${CVE_ID}" \
  --agent bacgenie-planner \
  -m "$MODEL" \
  "$PROMPT" < /dev/null

if [[ "${BACGENIE_AUTO_VERIFY:-0}" == "1" ]]; then
  python3 "$SCRIPT_DIR/pipeline.py" --stage post-reproduce --cve "$CVE_ID"
fi
