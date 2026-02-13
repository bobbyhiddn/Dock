#!/bin/bash
# Start cloudflared quick tunnel and capture the URL
# When the URL changes, update the Fly secret

FLYCTL="$HOME/.fly/bin/flyctl"
CLOUDFLARED="$HOME/.local/bin/cloudflared"
APP_NAME="hermit-dock"
UPSTREAM_PORT=7778
LOG_FILE="/tmp/cloudflared-hermit.log"

echo "Starting cloudflared tunnel to localhost:${UPSTREAM_PORT}..."

# Start cloudflared in background, capture output
$CLOUDFLARED tunnel --url "http://localhost:${UPSTREAM_PORT}" --no-autoupdate 2>&1 | tee "$LOG_FILE" &
CF_PID=$!

# Wait for the URL to appear in the output
echo "Waiting for tunnel URL..."
for i in $(seq 1 30); do
    TUNNEL_URL=$(grep -oP 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG_FILE" 2>/dev/null | head -1)
    if [ -n "$TUNNEL_URL" ]; then
        echo "Tunnel URL: $TUNNEL_URL"
        echo "$TUNNEL_URL" > /tmp/hermit-dock-tunnel-url.txt

        # Update Fly secret
        echo "Updating Fly app upstream URL..."
        $FLYCTL secrets set UPSTREAM_URL="$TUNNEL_URL" -a "$APP_NAME" 2>&1 || true

        echo "Done! Tunnel running at PID $CF_PID"
        echo "URL: $TUNNEL_URL"
        break
    fi
    sleep 2
done

if [ -z "$TUNNEL_URL" ]; then
    echo "ERROR: Failed to get tunnel URL after 60 seconds"
    kill $CF_PID 2>/dev/null
    exit 1
fi

# Wait for cloudflared to exit
wait $CF_PID
