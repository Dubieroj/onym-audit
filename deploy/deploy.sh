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
test -f keys/discovery.key || { echo "keys/discovery.key missing (onym-audit keygen -out keys/discovery.key)" >&2; exit 1; }
test -f public/manifest.json || { echo "run onym-audit publish first" >&2; exit 1; }

# Only committed code is built and tested: review checkouts, pulled orders
# and engine output hold other people's code, and `go test` runs whatever
# it compiles. Every package must have its Go files tracked by git.
for dir in $(go list -f '{{.Dir}}' ./...); do
  rel=${dir#"$PWD"/}
  if [ -z "$(git ls-files -- "$rel/*.go")" ] || [ -n "$(git ls-files --others --exclude-standard -- "$rel/*.go"; git ls-files --others --ignored --exclude-standard -- "$rel/*.go")" ]; then
    echo "refusing to test: $rel holds Go files that are not committed (review checkouts belong in reviews/, fenced by its go.mod)" >&2
    exit 1
  fi
done
go test ./...
node tools/verify-js-test.mjs >/dev/null
node tools/onym-id-test.mjs >/dev/null
node tools/stellar-test.mjs >/dev/null
python3 tools/build_landing.py --check
mkdir -p dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/onym-audit ./cmd/onym-audit

scp dist/onym-audit "$DEPLOY_HOST:/usr/local/bin/onym-audit.upload"
scp deploy/onym-audit.service "$DEPLOY_HOST:/etc/systemd/system/onym-audit.service"
scp deploy/onym-audit.nginx.conf "$DEPLOY_HOST:/etc/nginx/snippets/onym-audit.conf"
# Config and keys go through a root-only staging directory, never /tmp: no
# other user on the host can plant a file there for the steps below to install.
STAGE=/root/onym-audit-upload
ssh "$DEPLOY_HOST" "rm -rf $STAGE && install -d -m 700 $STAGE"
scp config.json "$DEPLOY_HOST:$STAGE/config.json"
ssh "$DEPLOY_HOST" 'test -f /etc/onym-audit/status.key' || scp keys/status.key "$DEPLOY_HOST:$STAGE/status.key"
ssh "$DEPLOY_HOST" 'test -f /etc/onym-audit/discovery.key' || scp keys/discovery.key "$DEPLOY_HOST:$STAGE/discovery.key"

ssh "$DEPLOY_HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
STAGE=/root/onym-audit-upload
id onym-audit >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin onym-audit
install -d -m 755 -o onym-audit -g onym-audit /var/lib/onym-audit /var/lib/onym-audit/site
install -d -m 700 -o onym-audit -g onym-audit /var/lib/onym-audit/inbox /var/lib/onym-audit/hub
install -d -m 750 -o root -g onym-audit /etc/onym-audit
install -m 640 -o root -g onym-audit "$STAGE/config.json" /etc/onym-audit/config.json
for k in status discovery; do
    if [ -f "$STAGE/$k.key" ]; then
        install -m 440 -o root -g onym-audit "$STAGE/$k.key" "/etc/onym-audit/$k.key"
    fi
done
rm -rf "$STAGE"
mv -f /usr/local/bin/onym-audit.upload /usr/local/bin/onym-audit
chmod 755 /usr/local/bin/onym-audit
REMOTE

rsync -rlt --exclude status.json --exclude status.json.sig --exclude responses/ --exclude discovery/catalogs/ \
    public/ "$DEPLOY_HOST:/var/lib/onym-audit/site/"

ssh "$DEPLOY_HOST" SITE_CONF="$SITE_CONF" 'bash -s' <<'REMOTE'
set -euo pipefail
# chown -R does not follow symlinks; permissions are then set as the service
# user, so a symlink it planted cannot make root change any other file.
chown -R onym-audit:onym-audit /var/lib/onym-audit/site
runuser -u onym-audit -- chmod -R u=rwX,go=rX /var/lib/onym-audit/site
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
