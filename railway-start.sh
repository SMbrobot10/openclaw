#!/bin/sh
set -e

# Ensure state directory and workspace exist
STATE_DIR="${OPENCLAW_STATE_DIR:-/data/.openclaw}"
WORKSPACE_DIR="${OPENCLAW_WORKSPACE_DIR:-/data/workspace}"
mkdir -p "$STATE_DIR"
mkdir -p "$WORKSPACE_DIR"

CONFIG_PATH="$STATE_DIR/openclaw.json"

# Always write config (overwrite) to ensure it stays in sync with env vars.
# OPENCLAW_GATEWAY_TOKEN and ANTHROPIC_API_KEY are read from env at runtime.
cat > "$CONFIG_PATH" <<'EOF'
{
  "gateway": {
    "auth": {
      "mode": "token"
    },
    "controlUi": {
      "enabled": true
    },
    "trustedProxies": ["100.64.0.0/10"]
  }
}
EOF
echo "Config written to $CONFIG_PATH"

# Start the gateway in the background
node openclaw.mjs gateway --allow-unconfigured --port 8080 --bind lan &
GATEWAY_PID=$!

# Wait for the gateway to accept connections
echo "Waiting for gateway to be ready..."
RETRIES=0
MAX_RETRIES=30
while [ $RETRIES -lt $MAX_RETRIES ]; do
  if node -e "const s=require('net').createConnection(8080,'127.0.0.1');s.on('connect',()=>{s.destroy();process.exit(0)});s.on('error',()=>process.exit(1))" 2>/dev/null; then
    echo "Gateway is accepting connections!"
    break
  fi
  RETRIES=$((RETRIES + 1))
  sleep 2
done

if [ $RETRIES -eq $MAX_RETRIES ]; then
  echo "Warning: Gateway port check timed out after ${MAX_RETRIES} retries"
fi

# Run the sidecar script to configure and auto-approve pairing requests
# This connects via loopback so device pairing is auto-approved.
echo "Starting setup sidecar..."
node setup-sidecar.mjs &

# Wait for the gateway process (foreground)
wait $GATEWAY_PID
