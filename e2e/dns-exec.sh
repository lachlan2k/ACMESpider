#!/bin/sh
# lego "exec" DNS provider shim: publishes/removes DNS-01 TXT records on dnsmock (e2e/dnsmock), which is
# what Pebble's validation authority queries. Arguments (lego default mode): <present|cleanup> <fqdn> <value>
# A trailing "--" separator is tolerated.
action="$1"; shift
[ "$1" = "--" ] && shift
fqdn="$1"; value="$2"
mgmt="${DNSMOCK_MGMT:-http://127.0.0.1:8055}"

case "$action" in
  present)
    curl -fsS -X POST -d "{\"host\":\"$fqdn\",\"value\":\"$value\"}" "$mgmt/set-txt" >/dev/null ;;
  cleanup)
    curl -fsS -X POST -d "{\"host\":\"$fqdn\"}" "$mgmt/clear-txt" >/dev/null ;;
  timeout)
    exit 1 ;;   # use lego's defaults
  *)
    echo "unknown action $action" >&2; exit 1 ;;
esac
