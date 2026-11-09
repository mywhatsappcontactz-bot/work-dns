#!/usr/bin/env bash
# Local spike deploy of the committed, built agent to /opt/work-dns for the systemd service.
# Keeps one rollback copy at /opt/work-dns.old. Starts nothing and changes no DNS settings.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/opt/work-dns
UNIT=work-dns-agent
cd "$SRC"

if systemctl is-active --quiet "$UNIT"; then
  echo "The service is running. Stop it first: sudo systemctl stop $UNIT"
  exit 1
fi
if [ -n "$(git status --porcelain apps packages)" ]; then
  echo "Uncommitted changes under apps or packages: commit them first, so the deployed code can be reproduced."
  git status --short apps packages
  exit 1
fi
COMMIT="$(git rev-parse --short HEAD)"
echo "Deploying commit $COMMIT on branch $(git branch --show-current)"
sudo -v

npm run build --workspaces --if-present > /tmp/deploy-build.log 2>&1 || { echo "build failed:"; tail -n 20 /tmp/deploy-build.log; exit 1; }

sudo rm -rf "$DEST.new"
sudo mkdir -p "$DEST.new"
tar -C "$SRC" --exclude=.git --exclude=spike-benchmark.ts -cf - . | sudo tar -C "$DEST.new" --no-same-owner -xf -
printf '%s %s\n' "$COMMIT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee "$DEST.new/DEPLOYED_COMMIT" > /dev/null
sudo chown -R root:root "$DEST.new"
sudo chmod -R go-w "$DEST.new"

CHECK=$(cd / && sudo -u work-dns node --input-type=module -e "const m = await import('$DEST.new/apps/agent/dist/index.js'); console.log([typeof m.runAgent, typeof m.SessionUserResolver, typeof m.AgentOutbox, typeof m.AgentEventSender].join(' '))") || CHECK="the load failed"
if [ "$CHECK" != "function function function function" ]; then
  echo "The staged copy failed its load check as the service account: $CHECK"
  sudo rm -rf "$DEST.new"
  exit 1
fi

sudo rm -rf "$DEST.old"
if [ -d "$DEST" ]; then sudo mv "$DEST" "$DEST.old"; fi
sudo mv "$DEST.new" "$DEST"

echo "deployed: $(cat "$DEST/DEPLOYED_COMMIT")"
ls -l "$DEST/apps/agent/dist/bin.js" "$DEST/apps/agent/dist/restore-bin.js" "$DEST/apps/agent/dist/session-user.js"
echo "--- installed unit file vs the repo copy:"
if diff -u /etc/systemd/system/work-dns-agent.service deploy/systemd/work-dns-agent.service; then echo "unit unchanged"; fi
echo "--- state directory:"
sudo ls -la /var/lib/work-dns
if sudo test -e /var/lib/work-dns/.config/work-dns/dns-backup.json; then echo "WARNING: a DNS backup file is left over from an earlier run"; fi
echo "Rollback copy kept at $DEST.old"
