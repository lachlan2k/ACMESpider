#!/usr/bin/env bash
# End-to-end tests: real ACME clients against ACMESpider, with Pebble as the upstream CA. Needs docker.
#
#   e2e/run.sh up                start pebble, a DNS mock and ACMESpider (rebuilds ACMESpider)
#   e2e/run.sh test [client...]  run client scenarios against a running stack (default: all)
#   e2e/run.sh down              tear everything down
#   e2e/run.sh all [client...]   up, test, down
#
# clients: lego (v5) lego4 certbot caddy acmesh traefik
#
# E2E_TARGET=pebble runs the same scenarios straight against Pebble instead of ACMESpider. Pebble implements
# everything (revocation, key rollover, account lookup...), so it is the reference: a "known gap" check should
# pass there, otherwise the check itself is wrong.
set -uo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_DIR="$E2E_ROOT/e2e"
export E2E_WORK="${E2E_WORK:-${TMPDIR:-/tmp}/acmespider-e2e}"
mkdir -p "$E2E_WORK/logs"

TARGET="${E2E_TARGET:-spider}"
NET=acmespider-e2e_default
EMAIL=e2e@example.com
COMPOSE=(docker compose -f "$E2E_DIR/docker-compose.yml")

case "$TARGET" in
  spider)
    DIR=https://acmespider.test/acme/directory
    HTTP_PORT=80                     # ACMESpider fetches http://<domain>/.well-known/... with no port
    TRUST_PEM="$E2E_WORK/pebble-root.pem" ;;   # the CA that issued ACMESpider's own certificate
  pebble)
    DIR=https://pebble:14000/dir
    HTTP_PORT=5002                   # pebble's validation authority
    TRUST_PEM="$E2E_WORK/pebble-test/test/certs/pebble.minica.pem" ;;
  *) echo "unknown E2E_TARGET $TARGET" >&2; exit 2 ;;
esac
ACCOUNT_DIR_NAME=$(echo "${DIR#https://}" | cut -d/ -f1 | tr ':' '_')   # how lego names the account directory

pass=0; fail=0; known=0; failures=()
log()  { printf '\033[1;34m[e2e]\033[0m %s\n' "$*" >&2; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); failures+=("$*"); }
# check "description" command...   (output goes to the scenario log)
check() { local d=$1; shift; if "$@" >>"$LOGFILE" 2>&1; then ok "$d"; else bad "$d"; fi; }
# expect_fail "description" command...   passes if the command fails
expect_fail() { local d=$1; shift; if "$@" >>"$LOGFILE" 2>&1; then bad "$d (unexpectedly succeeded)"; else ok "$d"; fi; }
# known_gap "description" command...   a feature ACMESpider doesn't have yet. Reported but not a failure; if it
# starts passing that's flagged so it can be promoted to a normal check. Against the pebble reference it must
# pass, since otherwise the check itself is broken.
known_gap() {
  local d=$1; shift
  if "$@" >>"$LOGFILE" 2>&1; then
    if [ "$TARGET" = pebble ]; then ok "$d"; else printf '  \033[35mNOW PASSES\033[0m %s (promote to check)\n' "$d"; pass=$((pass+1)); fi
  else
    if [ "$TARGET" = pebble ]; then bad "$d (fails against the reference, so the check is wrong)"; else printf '  \033[33mKNOWN GAP\033[0m %s\n' "$d"; known=$((known+1)); fi
  fi
}
scenario() { LOGFILE="$E2E_WORK/logs/$TARGET-$1.log"; : >"$LOGFILE"; log "== $1 [$TARGET]  (log: $LOGFILE)"; }

spider_logs() { "${COMPOSE[@]}" logs --no-color acmespider 2>&1; }
# how many accounts ACMESpider has created so far (newAccount answered 201)
spider_accounts_created() { spider_logs | grep 'URI=/acme/new-account' | grep -c 'status=201'; }

# --- clients ------------------------------------------------------------------------------------------------
trust_args() { printf '%s\n' -v "$TRUST_PEM:/ca.pem:ro" -e SSL_CERT_FILE=/ca.pem -e REQUESTS_CA_BUNDLE=/ca.pem -e LEGO_CA_CERTIFICATES=/ca.pem; }

# c_run a.test,b.test <docker run args...>: a throwaway client container on the test network, reachable by
# ACMESpider as each alias. Every run has a deadline (E2E_CLIENT_TIMEOUT seconds), so a client that stalls
# fails its check instead of hanging the suite.
c_run() { local aliases=() a; IFS=, read -ra aliases <<<"$1"; shift
  local args=(); for a in "${aliases[@]}"; do args+=(--network-alias "$a"); done
  local trust=(); while IFS= read -r a; do trust+=("$a"); done < <(trust_args)
  local name="e2e-client-$$-$RANDOM"
  # C_RUN_STDIN=1 keeps stdin attached so a prompt can be answered: printf 'y\n' | C_RUN_STDIN=1 c_run ...
  local stdin=(); [ -n "${C_RUN_STDIN:-}" ] && stdin=(-i)
  docker run --rm ${stdin[@]+"${stdin[@]}"} --name "$name" --network "$NET" "${args[@]}" "${trust[@]}" "$@" <&0 &
  local pid=$!
  ( sleep "${E2E_CLIENT_TIMEOUT:-240}"; echo "TIMED OUT after ${E2E_CLIENT_TIMEOUT:-240}s" >&2; docker kill "$name" >/dev/null 2>&1 ) &
  local watchdog=$!
  wait "$pid"; local rc=$?
  kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
  return $rc
}

# Client state lives in named volumes rather than bind mounts: bind mounts are racy on some docker VMs
vol_new()  { docker volume rm -f "$1" >/dev/null 2>&1; docker volume create "$1" >/dev/null; }
vol_cat()  { docker run --rm -v "$1:/v:ro" alpine:3 cat "/v/$2"; }
vol_find() { docker run --rm -v "$1:/v:ro" alpine:3 find /v -name "$2" 2>/dev/null | head -1 | sed 's#^/v/##'; }

# --- stack --------------------------------------------------------------------------------------------------
prepare() {
  if [ ! -f "$E2E_WORK/pebble-test/test/certs/pebble.minica.pem" ]; then
    log "extracting pebble's test CA"
    rm -rf "$E2E_WORK/pebble-test"; mkdir -p "$E2E_WORK/pebble-test"
    local id; id=$(docker create ghcr.io/letsencrypt/pebble:latest)
    docker cp "$id:/test" "$E2E_WORK/pebble-test/" >/dev/null; docker rm "$id" >/dev/null
  fi
  log "building ACMESpider and the DNS mock for linux"
  local arch; arch=$(docker info --format '{{.Architecture}}'); [ "$arch" = aarch64 ] && arch=arm64; [ "$arch" = x86_64 ] && arch=amd64
  rm -rf "$E2E_WORK/spider-build" "$E2E_WORK/dnsmock-build"; mkdir -p "$E2E_WORK/spider-build" "$E2E_WORK/dnsmock-build"
  (cd "$E2E_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$E2E_WORK/spider-build/acmespider" ./cmd) || return 1
  (cd "$E2E_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$E2E_WORK/dnsmock-build/dnsmock" ./e2e/dnsmock) || return 1
  cp "$E2E_DIR/dns-exec.sh" "$E2E_WORK/pebble-test/test/certs/pebble.minica.pem" "$E2E_WORK/spider-build/"
  docker build -q -t acmespider-e2e:local -f "$E2E_DIR/spider.Dockerfile" "$E2E_WORK/spider-build" >/dev/null
  docker build -q -t acmespider-e2e-dnsmock:local -f "$E2E_DIR/dnsmock.Dockerfile" "$E2E_WORK/dnsmock-build" >/dev/null
}

pebble_root() { curl -fsSk https://localhost:15000/roots/0; }

up() {
  prepare || exit 1
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  log "starting stack"
  "${COMPOSE[@]}" up -d >/dev/null 2>&1 || exit 1
  log "waiting for ACMESpider to obtain its own TLS certificate from the test CA (about 30-40s)"
  for i in $(seq 1 240); do
    "${COMPOSE[@]}" exec -T acmespider curl -fsSk https://acmespider.test/acme/directory >/dev/null 2>&1 && break
    sleep 0.5
    if [ "$i" = 240 ]; then log "ACMESpider never came up:"; spider_logs | tail -25; exit 1; fi
  done
  # pebble's root is generated fresh each run: clients need it to trust ACMESpider's certificate
  pebble_root >"$E2E_WORK/pebble-root.pem" || { log "couldn't fetch pebble's root"; exit 1; }
  log "stack is up"
}

down() {
  docker rm -f e2e-caddy e2e-traefik >/dev/null 2>&1
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  docker volume ls -q --filter name=e2e- | xargs -r docker volume rm -f >/dev/null 2>&1
}

# verify_cert <fullchain.pem> <domain>...  : the leaf covers exactly those domains and chains to pebble's root
verify_cert() {
  local pem=$1; shift
  [ -s "$pem" ] || { echo "no certificate at $pem"; return 1; }
  local root="$E2E_WORK/root.pem"; pebble_root >"$root" || return 1
  local leaf="$E2E_WORK/leaf.pem" chain="$E2E_WORK/chain.pem"; : >"$chain"
  awk -v leaf="$leaf" -v chain="$chain" 'BEGIN{n=0} /BEGIN CERT/{n++} {print > (n==1 ? leaf : chain)}' "$pem"
  local sans; sans=$(openssl x509 -in "$leaf" -noout -text | grep -A1 "Alternative Name" | tail -1 | tr -d ' ')
  echo "SANs: $sans"
  echo "issuer: $(openssl x509 -in "$leaf" -noout -issuer)  notAfter: $(openssl x509 -in "$leaf" -noout -enddate)"
  local want="" dom; for dom in "$@"; do want+="DNS:$dom,"; done
  local got; got=$(echo "$sans" | tr ',' '\n' | sort | tr '\n' ',')
  want=$(echo "$want" | tr ',' '\n' | sed '/^$/d' | sort | tr '\n' ',')
  [ "$got" = "$want" ] || { echo "SAN mismatch: got $got want $want"; return 1; }
  if [ -s "$chain" ]; then openssl verify -CAfile "$root" -untrusted "$chain" "$leaf"; else openssl verify -CAfile "$root" "$leaf"; fi
}
# verify_vol <volume> <path in volume> <domain>...
verify_vol() { local vol=$1 path=$2; shift 2; vol_cat "$vol" "$path" >"$E2E_WORK/fetched.pem" && verify_cert "$E2E_WORK/fetched.pem" "$@"; }
serial_of() { vol_cat "$1" "$2" | openssl x509 -noout -serial; }

# ---------------------------------------------------------------------------------------------------------
t_lego() {
  scenario lego
  local vol="e2e-$TARGET-lego"; vol_new "$vol"
  # lego v5: `run` obtains a certificate, or renews it when it is due. Subcommands take fewer flags than `run`.
  local srv=(--server "$DIR" --email "$EMAIL" --path /data)
  local run=("${srv[@]}" --accept-tos --http --http.address ":$HTTP_PORT")
  lego() { c_run "${LEGO_ALIASES:-lego.test}" -v "$vol:/data" goacme/lego "$@"; }

  check "lego: register an account and issue a certificate" lego run "${run[@]}" -d lego.test
  check "lego: certificate covers lego.test and chains to the CA" verify_vol "$vol" certificates/lego.test.crt lego.test
  check "lego: running again with a fresh certificate is a no-op" lego run "${run[@]}" -d lego.test
  local before; before=$(serial_of "$vol" certificates/lego.test.crt)
  check "lego: forced renewal issues a new certificate" lego run "${run[@]}" -d lego.test --renew-force --no-random-sleep
  check "lego: the renewed certificate has a new serial" test "$(serial_of "$vol" certificates/lego.test.crt)" != "$before"
  check "lego: renewed certificate is good" verify_vol "$vol" certificates/lego.test.crt lego.test
  LEGO_ALIASES=lego.test,lego2.test check "lego: multi-domain (SAN) certificate" lego run "${run[@]}" -d lego.test -d lego2.test --cert.name san
  check "lego: SAN certificate covers both names" verify_vol "$vol" certificates/san.crt lego.test lego2.test
  check "lego: listing accounts" lego accounts list --path /data

  # newAccount with onlyReturnExisting must hand back the existing account rather than create another (RFC 8555 7.3.1)
  recover_existing() {
    local key="/data/accounts/$ACCOUNT_DIR_NAME/$EMAIL/$EMAIL.key" before after
    [ "$TARGET" = spider ] && before=$(spider_accounts_created)
    printf 'y\n' | C_RUN_STDIN=1 lego accounts recover "${srv[@]}" --private-key "$key" || return 1
    if [ "$TARGET" = spider ]; then
      after=$(spider_accounts_created)
      [ "$before" = "$after" ] || { echo "recovery created $((after-before)) new account(s) instead of finding the existing one"; return 1; }
    fi
  }
  known_gap "lego: account recovery by key (newAccount onlyReturnExisting, RFC 8555 7.3.1)" recover_existing
  rollover() { printf 'y\n' | C_RUN_STDIN=1 lego accounts keyrollover "${srv[@]}"; }
  known_gap "lego: account key rollover (keyChange, RFC 8555 7.3.5)" rollover
  known_gap "lego: revoking a certificate (revokeCert, RFC 8555 7.6)" lego certificates revoke "${srv[@]}" --cert.name lego.test

  # A name nothing answers for: the client must see a failure, not hang
  local t0=$SECONDS
  expect_fail "lego: an unreachable domain fails the order" lego run "${run[@]}" -d nobody.test --cert.timeout 5
  echo "failed challenge took $((SECONDS - t0))s to surface" >>"$LOGFILE"
}

# ---------------------------------------------------------------------------------------------------------
t_lego4() {
  scenario lego4
  local vol="e2e-$TARGET-lego4"; vol_new "$vol"
  # lego v4 has a different CLI from v5: global flags, then a `run` / `renew` / `revoke` command
  local flags=(--server "$DIR" --email "$EMAIL" --accept-tos --http --http.port ":$HTTP_PORT" --path /data)
  lego4() { c_run lego4.test -v "$vol:/data" goacme/lego:v4.25.2 "$@"; }

  check "lego v4: register an account and issue a certificate" lego4 "${flags[@]}" -d lego4.test run
  check "lego v4: certificate covers lego4.test and chains to the CA" verify_vol "$vol" certificates/lego4.test.crt lego4.test
  local before; before=$(serial_of "$vol" certificates/lego4.test.crt)
  check "lego v4: renewing works" lego4 "${flags[@]}" -d lego4.test renew --days 100 --no-random-sleep
  check "lego v4: the renewed certificate has a new serial" test "$(serial_of "$vol" certificates/lego4.test.crt)" != "$before"
  known_gap "lego v4: revoking a certificate (revokeCert, RFC 8555 7.6)" lego4 "${flags[@]}" -d lego4.test revoke
}

# ---------------------------------------------------------------------------------------------------------
t_certbot() {
  scenario certbot
  local vol="e2e-$TARGET-certbot"; vol_new "$vol"
  certbot() { c_run "${CERTBOT_ALIASES:-certbot.test}" -v "$vol:/etc/letsencrypt" certbot/certbot "$@"; }
  local common=(--non-interactive --agree-tos -m "$EMAIL" --server "$DIR" --standalone --preferred-challenges http --http-01-port "$HTTP_PORT")

  check "certbot: register an account and issue a certificate" certbot certonly "${common[@]}" -d certbot.test
  check "certbot: certificate covers certbot.test and chains to the CA" verify_vol "$vol" live/certbot.test/fullchain.pem certbot.test
  local before; before=$(serial_of "$vol" live/certbot.test/cert.pem)
  check "certbot: forced renewal" certbot renew --force-renewal --no-random-sleep-on-renew
  check "certbot: the renewed certificate has a new serial" test "$(serial_of "$vol" live/certbot.test/cert.pem)" != "$before"
  CERTBOT_ALIASES=certbot.test,certbot2.test check "certbot: multi-domain (SAN) certificate" certbot certonly "${common[@]}" --cert-name san -d certbot.test -d certbot2.test
  check "certbot: SAN certificate covers both names" verify_vol "$vol" live/san/fullchain.pem certbot.test certbot2.test
  check "certbot: showing the account" certbot show_account --server "$DIR"

  known_gap "certbot: revoking a certificate (revokeCert, RFC 8555 7.6)" certbot revoke --non-interactive --no-delete-after-revoke --server "$DIR" --cert-path /etc/letsencrypt/live/certbot.test/cert.pem
  check "certbot: unregistering the account (account deactivation, RFC 8555 7.3.6)" certbot unregister --non-interactive --server "$DIR"
}

# ---------------------------------------------------------------------------------------------------------
t_caddy() {
  scenario caddy
  local vol="e2e-$TARGET-caddy"; vol_new "$vol"
  local cfg="$E2E_WORK/caddy-Caddyfile"
  cat >"$cfg" <<CADDY
{
	acme_ca $DIR
	acme_ca_root /ca.pem
	email $EMAIL
	http_port $HTTP_PORT
	admin off
}
caddy.test {
	respond "hello from caddy"
}
CADDY
  docker rm -f e2e-caddy >/dev/null 2>&1
  local trust=(); while IFS= read -r a; do trust+=("$a"); done < <(trust_args)
  docker run -d --name e2e-caddy --network "$NET" --network-alias caddy.test "${trust[@]}" \
    -v "$cfg:/etc/caddy/Caddyfile:ro" -v "$vol:/data" caddy:2 >/dev/null

  local crt=""
  for i in $(seq 1 120); do
    crt=$(vol_find "$vol" 'caddy.test.crt'); [ -n "$crt" ] && break
    sleep 1
  done
  docker logs e2e-caddy >>"$LOGFILE" 2>&1
  check "caddy: obtained a certificate for caddy.test" test -n "$crt"
  [ -n "$crt" ] && check "caddy: certificate covers caddy.test and chains to the CA" verify_vol "$vol" "$crt" caddy.test
  check "caddy: logged a successful issuance" grep -q "certificate obtained successfully" "$LOGFILE"
  docker rm -f e2e-caddy >/dev/null 2>&1
}

# ---------------------------------------------------------------------------------------------------------
t_acmesh() {
  scenario acmesh
  local vol="e2e-$TARGET-acmesh"; vol_new "$vol"
  acmesh() { c_run acmesh.test -v "$vol:/acme.sh" neilpang/acme.sh acme.sh "$@"; }
  local common=(--server "$DIR" --ca-bundle /ca.pem --accountemail "$EMAIL")

  check "acme.sh: register an account and issue a certificate" acmesh --issue "${common[@]}" -d acmesh.test --standalone --httpport "$HTTP_PORT"
  local crt; crt=$(vol_find "$vol" 'fullchain.cer')
  check "acme.sh: certificate covers acmesh.test and chains to the CA" verify_vol "$vol" "${crt:-missing}" acmesh.test
  check "acme.sh: forced renewal" acmesh --renew "${common[@]}" -d acmesh.test --standalone --httpport "$HTTP_PORT" --force
  known_gap "acme.sh: revoking a certificate (revokeCert, RFC 8555 7.6)" acmesh --revoke "${common[@]}" -d acmesh.test
  check "acme.sh: deactivating the account (RFC 8555 7.3.6)" acmesh --deactivate-account "${common[@]}"
}

# ---------------------------------------------------------------------------------------------------------
t_traefik() {
  scenario traefik
  local vol="e2e-$TARGET-traefik"; vol_new "$vol"
  local dir="$E2E_WORK/traefik-cfg"; rm -rf "$dir"; mkdir -p "$dir"
  cat >"$dir/traefik.yml" <<YAML
entryPoints:
  web: {address: ":$HTTP_PORT"}
  websecure: {address: ":443"}
certificatesResolvers:
  le:
    acme:
      email: $EMAIL
      storage: /data/acme.json
      caServer: $DIR
      httpChallenge: {entryPoint: web}
providers:
  file: {filename: /etc/traefik/dynamic.yml}
log: {level: DEBUG}
YAML
  cat >"$dir/dynamic.yml" <<'YAML'
http:
  routers:
    site:
      rule: Host(`traefik.test`)
      entryPoints: [websecure]
      service: noop@internal
      tls: {certResolver: le}
YAML
  docker rm -f e2e-traefik >/dev/null 2>&1
  local trust=(); while IFS= read -r a; do trust+=("$a"); done < <(trust_args)
  docker run -d --name e2e-traefik --network "$NET" --network-alias traefik.test "${trust[@]}" \
    -v "$dir/traefik.yml:/etc/traefik/traefik.yml:ro" -v "$dir/dynamic.yml:/etc/traefik/dynamic.yml:ro" -v "$vol:/data" traefik:v3 >/dev/null

  local have=0
  for i in $(seq 1 120); do
    have=$(vol_cat "$vol" acme.json 2>/dev/null | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(sum(len(r.get("Certificates") or []) for r in d.values()))
except Exception: print(0)')
    [ "${have:-0}" -gt 0 ] && break
    sleep 1
  done
  docker logs e2e-traefik >>"$LOGFILE" 2>&1
  check "traefik: obtained a certificate for traefik.test" test "${have:-0}" -gt 0
  if [ "${have:-0}" -gt 0 ]; then
    vol_cat "$vol" acme.json | python3 -c 'import json,sys,base64
d=json.load(sys.stdin); c=next(c for r in d.values() for c in r["Certificates"])
sys.stdout.buffer.write(base64.b64decode(c["certificate"]))' >"$E2E_WORK/traefik-fullchain.pem"
    check "traefik: certificate covers traefik.test and chains to the CA" verify_cert "$E2E_WORK/traefik-fullchain.pem" traefik.test
  fi
  docker rm -f e2e-traefik >/dev/null 2>&1
}

# ---------------------------------------------------------------------------------------------------------
run_all() {
  local clients=("$@"); [ ${#clients[@]} -eq 0 ] && clients=(lego lego4 certbot caddy acmesh traefik)
  [ "$TARGET" = pebble ] && pebble_root >/dev/null 2>&1 || { [ "$TARGET" = pebble ] && { log "pebble isn't running (e2e/run.sh up)"; return 1; }; }
  for c in "${clients[@]}"; do "t_$c"; done
  echo
  log "[$TARGET] passed: $pass  failed: $fail  known gaps: $known"
  for f in "${failures[@]:-}"; do [ -n "$f" ] && echo "  - $f"; done
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  up)   up ;;
  down) down ;;
  test) shift; run_all "$@" ;;
  all)  shift; up; run_all "$@"; rc=$?; down; exit $rc ;;
  *)    sed -n '2,15p' "$0"; exit 2 ;;
esac
