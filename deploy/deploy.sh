#!/usr/bin/env bash
# deploy/deploy.sh — install or update the onym-audit seat on the VPS.
#
# What goes where:
#   - the auditor key NEVER leaves this machine (keys/auditor.key);
#   - the delegated status key is installed once as /etc/onym-audit/status.key;
#   - the published tree (public/) is pushed without --delete, and without
#     status.json or responses/, which the server owns.
# Safe to re-run: backs up the nginx site and restores it if `nginx -t` fails.
#
# Env overrides:
#   DEPLOY_HOST — ssh target (default: root@69.62.114.87)
#   SITE_CONF   — nginx site that includes the snippet (default: /etc/nginx/sites-enabled/foldy.io)

set -euo pipefail
cd "$(dirname "$0")/.."

DEPLOY_HOST="${DEPLOY_HOST:-root@69.62.114.87}"
SITE_CONF="${SITE_CONF:-/etc/nginx/sites-enabled/foldy.io}"

test -f config.json || { echo "config.json missing" >&2; exit 1; }
test -f keys/status.key || { echo "keys/status.key missing" >&2; exit 1; }
test -f public/manifest.json || { echo "run onym-audit publish first" >&2; exit 1; }

go test ./...
node tools/verify-js-test.mjs >/dev/null
python3 tools/build_landing.py --check
mkdir -p dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/onym-audit ./cmd/onym-audit

scp dist/onym-audit "$DEPLOY_HOST:/usr/local/bin/onym-audit.upload"
scp deploy/onym-audit.service "$DEPLOY_HOST:/etc/systemd/system/onym-audit.service"
scp deploy/onym-audit.nginx.conf "$DEPLOY_HOST:/etc/nginx/snippets/onym-audit.conf"
scp config.json "$DEPLOY_HOST:/tmp/onym-audit.config.json"
ssh "$DEPLOY_HOST" 'test -f /etc/onym-audit/status.key' || scp keys/status.key "$DEPLOY_HOST:/tmp/onym-audit.status.key"

ssh "$DEPLOY_HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
id onym-audit >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin onym-audit
install -d -m 755 -o onym-audit -g onym-audit /var/lib/onym-audit /var/lib/onym-audit/site
install -d -m 700 -o onym-audit -g onym-audit /var/lib/onym-audit/inbox
install -d -m 750 -o root -g onym-audit /etc/onym-audit
install -m 640 -o root -g onym-audit /tmp/onym-audit.config.json /etc/onym-audit/config.json
rm -f /tmp/onym-audit.config.json
if [ -f /tmp/onym-audit.status.key ]; then
    install -m 440 -o root -g onym-audit /tmp/onym-audit.status.key /etc/onym-audit/status.key
    rm -f /tmp/onym-audit.status.key
fi
mv -f /usr/local/bin/onym-audit.upload /usr/local/bin/onym-audit
chmod 755 /usr/local/bin/onym-audit
REMOTE

rsync -rlt --exclude status.json --exclude status.json.sig --exclude responses/ \
    public/ "$DEPLOY_HOST:/var/lib/onym-audit/site/"

ssh "$DEPLOY_HOST" SITE_CONF="$SITE_CONF" 'bash -s' <<'REMOTE'
set -euo pipefail
chown -R onym-audit:onym-audit /var/lib/onym-audit/site
find /var/lib/onym-audit/site -type d -exec chmod 755 {} +
find /var/lib/onym-audit/site -type f -exec chmod 644 {} +
if ! grep -q "snippets/onym-audit.conf" "$SITE_CONF"; then
    mkdir -p /root/nginx-backups
    BACKUP="/root/nginx-backups/$(basename "$SITE_CONF").$(date +%Y%m%d-%H%M%S)"
    cp "$SITE_CONF" "$BACKUP"
    sed -i 's#^\(\s*\)include /etc/nginx/snippets/foldy-vpn.conf;#&\n\1include /etc/nginx/snippets/onym-audit.conf;#' "$SITE_CONF"
    if ! grep -q "snippets/onym-audit.conf" "$SITE_CONF" || ! nginx -t; then
        cp "$BACKUP" "$SITE_CONF"
        echo "nginx change failed, restored $SITE_CONF from $BACKUP" >&2
        exit 1
    fi
    echo "nginx: added onym-audit include (backup: $BACKUP)"
fi
nginx -t
systemctl daemon-reload
systemctl enable onym-audit >/dev/null 2>&1
systemctl restart onym-audit
systemctl reload nginx
sleep 2
systemctl --no-pager --lines=8 status onym-audit
REMOTE
