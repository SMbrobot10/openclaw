#!/bin/sh
set -e

# Ensure state directory exists
mkdir -p "${OPENCLAW_STATE_DIR:-/data/.openclaw}"

CONFIG_PATH="${OPENCLAW_STATE_DIR:-/data/.openclaw}/openclaw.json"

# Write initial config if none exists
if [ ! -f "$CONFIG_PATH" ]; then
  cat > "$CONFIG_PATH" <<'EOF'
{
  "gateway": {
    "auth": {
      "mode": "token"
    },
    "controlUi": {
      "dangerouslyDisableDeviceAuth": true
    }
  }
}
EOF
  echo "Wrote initial config to $CONFIG_PATH"
else
  echo "Config already exists at $CONFIG_PATH"
fi

# Start the gateway
exec node openclaw.mjs gateway --allow-unconfigured --port 8080 --bind lan
