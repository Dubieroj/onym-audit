#!/usr/bin/env bash
# tools/sandbox.sh — the whole audit lifecycle on your machine, with throwaway
# keys and no network writes: publish an auditor, issue an attestation about a
# made-up component, verify it as a relying client, let the subject reply
# through the running server, supersede it, revoke the successor, and verify
# after each step.
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o bin/onym-audit ./cmd/onym-audit
B="$PWD/bin/onym-audit"
T="$(mktemp -d)"; trap 'kill $SRV 2>/dev/null || true; rm -rf "$T"' EXIT
cp -R public "$T/site"; rm -rf "$T/site/attestations" "$T/site/revocations" "$T/site/responses" "$T/site/reports" "$T/site/status.json"*
cd "$T"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "keys (throwaway)"
AUD=$($B keygen -out keys/auditor.key | head -1); $B keygen -out keys/status.key >/dev/null
SUBJ=$($B keygen -out keys/subject.key | head -1)
echo "auditor $AUD"; echo "subject $SUBJ"

cat > config.json <<JSON
{"baseUri":"https://sandbox.example.org/","componentId":"onym:component:sandbox-auditor","displayName":"Sandbox Auditor","contact":"mailto:sandbox@example.org","validUntil":"2030-01-01T00:00:00Z","offers":[],"methodologies":[{"class":"conformance-run","specification":"methodology/conformance-run.md","scopesOffered":["discovery.static-ed25519.provider"]}]}
JSON
echo '{"seat":"discovery","sandbox":true}' > component-manifest.json
$B publish -root site -config config.json -key keys/auditor.key -status-key keys/status.key

say "issue an attestation (fail) about the sandbox component"
python3 - "$SUBJ" "$AUD" <<'PY'
import json,hashlib,sys,datetime
subj,aud=sys.argv[1],sys.argv[2]
d=lambda p:'sha256:'+hashlib.sha256(open(p,'rb').read()).hexdigest()
now=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
f=lambda t:t.strftime('%Y-%m-%dT%H:%M:%SZ')
ref=lambda p:{"uri":"https://sandbox.example.org/"+p,"digest":d('site/'+p)}
def draft(i,result,summary,sup=None):
    return {"attestationVersion":1,"attestationId":i,"subject":"onym:component:sandbox-component","subjectOperator":subj,
     "artifact":{"kind":"deployment","source":"https://component.example.org/manifest.json","revision":d('component-manifest.json'),"artifactHash":None},
     "methodologyClass":"conformance-run","methodology":ref("methodology/conformance-run.md"),"scope":ref("scopes/discovery-static-ed25519-provider.md"),
     "scopeSummary":"sandbox run","exclusions":["everything outside the sandbox"],"result":result,"severityScale":ref("severity-v1.json"),"severityFloor":"low",
     "findingsReport":None,"findingsSummary":summary,"engagement":"unsolicited","sponsor":aud,"sponsorName":"Sandbox Auditor (self-funded)","relationships":"none","orderRef":None,
     "unsolicited":{"policy":d('site/policies/unsolicited.md'),"subjectContact":"mailto:security@component.example.org","subjectNotifiedAt":f(now-datetime.timedelta(hours=13)),"embargoUntil":None},
     "issuedAt":f(now-datetime.timedelta(minutes=5)),"expiresAt":f(now+datetime.timedelta(days=30)),"supersedes":sup}
json.dump(draft("sandbox-attestation-0001","fail",{"high":1}),open('a1.json','w'))
json.dump(draft("sandbox-attestation-0002","clear",{},"sandbox-attestation-0001"),open('a2.json','w'))
PY
$B attest -root site -config config.json -key keys/auditor.key -in a1.json
V="$B verify -manifest site/manifest.json -status site/status.json -target https://component.example.org/manifest.json -target-file component-manifest.json -credit $AUD"

say "start the server (status re-signing + write endpoints) on 127.0.0.1:18787"
$B serve -root site -config config.json -status-key keys/status.key -inbox inbox -listen 127.0.0.1:18787 & SRV=$!
sleep 1

say "the subject replies through POST /responses"
$B respond -attestation site/attestations/sandbox-attestation-0001.json -key keys/subject.key -id sandbox-reply-000001 -text "Fixed in the next release." -out reply.json
curl -s --data-binary @reply.json http://127.0.0.1:18787/responses; echo

say "a forged reply (wrong key) is refused"
$B respond -attestation site/attestations/sandbox-attestation-0001.json -key keys/status.key -id sandbox-reply-000002 -text "x" -out bad.json 2>&1 | tail -1 || true

say "an order signed by subject and sponsor is queued by POST /orders"
SPON=$($B keygen -out keys/sponsor.key | head -1)
python3 - "$SPON" <<'PY'
import json,hashlib,sys
spon=sys.argv[1]; d=lambda p:'sha256:'+hashlib.sha256(open(p,'rb').read()).hexdigest()
json.dump({"orderVersion":1,"orderId":"sandbox-order-000001","auditor":"onym:component:sandbox-auditor","subject":"onym:component:sandbox-component","sponsor":spon,
 "artifact":{"kind":"deployment","source":"https://component.example.org/manifest.json","revision":d('component-manifest.json'),"artifactHash":None},
 "methodologyClass":"conformance-run","scope":{"uri":"https://sandbox.example.org/scopes/discovery-static-ed25519-provider.md","digest":d('site/scopes/discovery-static-ed25519-provider.md')},
 "cooperation":"public deployment only","disclosure":{"findingsToSubjectFirst":True,"embargoDays":90,"attestationPublication":"public-on-issuance","failPublication":"public-after-embargo"},
 "timeline":{"start":"2026-09-24","reportDue":"2026-09-25"},"fee":{"model":"pro-bono","offerId":"conformance-run-discovery"},"signatures":[]},open('order.json','w'))
PY
$B sign-order -in order.json -role subject -key keys/subject.key -out order.json
$B sign-order -in order.json -role sponsor -key keys/sponsor.key -out order.json
curl -s --data-binary @order.json http://127.0.0.1:18787/orders; echo

say "verify as a relying client: fail is shown, with the subject's reply"
curl -s http://127.0.0.1:18787/status.json > site/status.json.fetched
$B verify -manifest site/manifest.json -status site/status.json.fetched -attestation site/attestations/sandbox-attestation-0001.json -target https://component.example.org/manifest.json -target-file component-manifest.json -response reply.json -credit "$AUD" 2>&1 | sed 's/^/  /' 

say "supersede with a clear re-run, re-sign, verify both"
$B attest -root site -config config.json -key keys/auditor.key -in a2.json
kill -HUP $SRV; sleep 1
curl -s http://127.0.0.1:18787/status.json > site/status.json.fetched
for id in 0001 0002; do echo "  sandbox-attestation-$id:"; $B verify -manifest site/manifest.json -status site/status.json.fetched -attestation site/attestations/sandbox-attestation-$id.json -target https://component.example.org/manifest.json -target-file component-manifest.json -credit "$AUD" 2>&1 | head -2 | sed 's/^/    /'; done

say "revoke the successor, verify again"
$B revoke -root site -config config.json -key keys/auditor.key -id sandbox-attestation-0002 -reason withdrawal
kill -HUP $SRV; sleep 1
curl -s http://127.0.0.1:18787/status.json > site/status.json.fetched
$B verify -manifest site/manifest.json -status site/status.json.fetched -attestation site/attestations/sandbox-attestation-0002.json -target https://component.example.org/manifest.json -target-file component-manifest.json -credit "$AUD" 2>&1 | head -3 | sed 's/^/  /'

say "the manifest's bytes change: the attestation stops applying"
echo '{"seat":"discovery","sandbox":"v2"}' > component-manifest.json
$B verify -manifest site/manifest.json -status site/status.json.fetched -attestation site/attestations/sandbox-attestation-0001.json -target https://component.example.org/manifest.json -target-file component-manifest.json -credit "$AUD" 2>&1 | head -3 | sed 's/^/  /'
say "done"
