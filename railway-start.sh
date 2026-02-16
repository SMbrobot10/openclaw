#!/bin/sh
set -e

# Ensure state directory and workspace exist
mkdir -p "${OPENCLAW_STATE_DIR:-/data/.openclaw}"
mkdir -p "${OPENCLAW_WORKSPACE_DIR:-/data/workspace}"

CONFIG_PATH="${OPENCLAW_STATE_DIR:-/data/.openclaw}/openclaw.json"

# Always write config (overwrite) to ensure it stays in sync with env vars.
# OPENCLAW_GATEWAY_TOKEN and ANTHROPIC_API_KEY are read from env at runtime.
cat > "$CONFIG_PATH" <<'EOF'
{
  "gateway": {
    "auth": {
      "mode": "token"
    },
    "controlUi": {
      "allowInsecureAuth": true
    }
  }
}
EOF
echo "Config written to $CONFIG_PATH"

# Start the gateway
exec node openclaw.mjs gateway --allow-unconfigured --port 8080 --bind lan
