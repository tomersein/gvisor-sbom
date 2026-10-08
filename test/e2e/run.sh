#!/usr/bin/env bash
# End-to-end test. Runs on a Kubernetes node that has gVisor (runsc) and a
# RuntimeClass named "gvisor", as root, because node mode reads runsc's state.
#
#   BIN=path/to/gvsbom-linux-<arch> sudo -E test/e2e/run.sh
#
# Optional: KUBECTL (default "kubectl"), KUBECONFIG, NODE (default hostname),
# KEEP=1 to leave the fixtures running afterwards.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
: "${BIN:?set BIN to the gvsbom binary}"
KUBECTL=${KUBECTL:-kubectl}
NODE=${NODE:-$(hostname)}
NS=gvsbom-e2e
work=$(mktemp -d)
kc() { $KUBECTL "$@"; }
gvsbom() { "$BIN" ${KUBECONFIG:+--kubeconfig "$KUBECONFIG"} -n "$NS" "$@"; }

passed=0 failed=0
check() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		echo "  ✓ $desc"
		passed=$((passed + 1))
	else
		echo "  ✗ $desc"
		failed=$((failed + 1))
	fi
}

# jq over a summary.json: q FILE POD FILTER, where FILTER sees one result.
q() { jq -e --arg p "$2" ".[] | select(.target.pod == \$p) | $3" "$1"; }
added() { [ "$(jq -r --arg p "$2" '[.[] | select(.target.pod == $p) | .drift.added[]?.name] | sort | join(",")' "$1")" = "$3" ]; }
removed() { [ "$(jq -r --arg p "$2" '[.[] | select(.target.pod == $p) | .drift.removed[]?.name] | sort | join(",")' "$1")" = "$3" ]; }
absent() { [ -s "$1" ] && ! jq -e --arg p "$2" 'any(.[]; .target.pod == $p)' "$1"; }
scanned() { [ "$(jq length "$1")" -eq "$2" ]; }

cleanup() {
	rm -rf "$work"
	if [ "${KEEP:-}" != 1 ]; then
		kc delete namespace "$NS" --wait=false >/dev/null 2>&1
	fi
}
trap cleanup EXIT

echo "== fixtures on node $NODE"
sed "s/__NODE__/$NODE/" "$here/fixtures.yaml" | kc apply -f - >/dev/null || exit 1
kc -n "$NS" wait --for=condition=Ready pod --all --timeout=300s >/dev/null || exit 1
for pod in $(kc -n "$NS" get pods -l '!gvsbom-e2e/no-ready-log' -o name); do
	for _ in $(seq 1 100); do
		kc -n "$NS" logs "$pod" 2>/dev/null | grep -qx ready && continue 2
		sleep 3
	done
	echo "  $pod never logged ready"
	exit 1
done
echo "  all fixtures ready"

echo "== exec mode"
gvsbom -o "$work/exec" --json >/dev/null 2>&1
s=$work/exec/summary.json
check "all 6 gVisor containers scanned" scanned "$s" 6
check "runc pod is not scanned" absent "$s" e2e-runc
check "e2e-add: the 5 pinned packages are added" added "$s" e2e-add "certifi,charset-normalizer,idna,requests,urllib3"
check "e2e-add: nothing removed or changed" q "$s" e2e-add '(.drift.removed | length) == 0 and (.drift.changed | length) == 0'
check "e2e-change: netbase removed" removed "$s" e2e-change "netbase"
check "e2e-change: pip changed to 24.0" q "$s" e2e-change '(.drift.changed | length) == 1 and .drift.changed[0].name == "pip" and .drift.changed[0].toVersion == "24.0"'
check "e2e-notar: image only, no errors" q "$s" e2e-notar '.runtimeUnavailable == true and (.errors | length) == 0'
check "e2e-vol: /tmp package found, volume package skipped" added "$s" e2e-vol "colorama"
check "e2e-vol: service account token not copied" q "$s" e2e-vol 'any(.excluded[]; .path == "/run/secrets/kubernetes.io/serviceaccount" and .reason == "secret or config volume")'
check "e2e-vol: secret volume not copied" q "$s" e2e-vol 'any(.excluded[]; .path == "/etc/creds" and .reason == "secret or config volume")'
check "e2e-evil: planted package found" q "$s" e2e-evil 'any(.drift.added[]; .name | startswith("evil"))'
check "e2e-liar: exec mode is fooled (requests hidden)" q "$s" e2e-liar '.drift != null and (.errors | length) == 0 and all(.drift.added[]?; .name != "requests")'

echo "== exec mode, --include-volumes --keep-rootfs"
gvsbom --pod e2e-vol --include-volumes --keep-rootfs -o "$work/vol" --json >/dev/null 2>&1
s=$work/vol/summary.json
r=$work/vol/$NS/e2e-vol/app/rootfs
check "volume package now found" added "$s" e2e-vol "colorama,six"
check "copy has /tmp and the emptyDir" test -e "$r/tmp/tools/colorama" -a -e "$r/opt/venv/six.py"
check "copy has no service account token" test ! -e "$r/run/secrets/kubernetes.io/serviceaccount/token"
check "copy has no secret" test ! -e "$r/etc/creds/password"
check "copy has no executable or setuid files" test -z "$(find "$r" -type f -perm /7111 -print -quit)"

echo "== exec mode, terminal output"
gvsbom --pod e2e-evil -o "$work/evil" >"$work/evil.txt" 2>/dev/null
check "report shows the planted package" grep -q "evil" "$work/evil.txt"
check "report contains no escape or carriage-return bytes" test "$(tr -dc '\033\r' <"$work/evil.txt" | wc -c)" -eq 0

echo "== node mode"
gvsbom --mode node --node "$NODE" -o "$work/node" --json >/dev/null 2>&1
s=$work/node/summary.json
check "all 6 gVisor containers scanned" scanned "$s" 6
check "runc pod is not scanned" absent "$s" e2e-runc
check "e2e-add: same 5 packages as exec mode" added "$s" e2e-add "certifi,charset-normalizer,idna,requests,urllib3"
check "e2e-change: netbase removed" removed "$s" e2e-change "netbase"
check "e2e-change: pip changed to 24.0, not listed twice" q "$s" e2e-change '(.drift.changed | length) == 1 and .drift.changed[0].name == "pip" and .drift.changed[0].toVersion == "24.0" and (.drift.added | length) == 0'
check "e2e-notar: runtime SBOM without tar" q "$s" e2e-notar '.runtimeUnavailable != true and (.errors | length) == 0 and .runtimeSBOM != null'
check "e2e-vol: /tmp and the emptyDir reported as not covered" q "$s" e2e-vol 'any(.notCovered[]; startswith("/tmp")) and any(.notCovered[]; startswith("/opt/venv"))'
check "e2e-liar: node mode is not fooled (requests found)" q "$s" e2e-liar 'any(.drift.added[]; .name == "requests")'
check "upper layers are smaller than exec copies" test "$(q "$s" e2e-add '.rootfs.Bytes')" -lt "$(q "$work/exec/summary.json" e2e-add '.rootfs.Bytes')"

echo "== limits and exit codes"
gvsbom --pod e2e-add --skip-image --max-entries 100 -o "$work/lim" --json >/dev/null 2>&1
check "--max-entries stops the copy" q "$work/lim/summary.json" e2e-add 'any(.errors[]; test("entry limit"))'
gvsbom --pod e2e-add --timeout 1s -o "$work/to" --json >/dev/null 2>&1
check "--timeout stops the scan" q "$work/to/summary.json" e2e-add 'any(.errors[]; test("timed out"))'
gvsbom --pod e2e-add --fail-on-drift -o "$work/fod" >/dev/null 2>&1
check "--fail-on-drift exits 3" test $? -eq 3
check "node mode without a node name is a usage error (exit 2)" test "$(NODE_NAME= "$BIN" --mode node >/dev/null 2>&1; echo $?)" -eq 2

echo
echo "passed: $passed, failed: $failed"
[ "$failed" -eq 0 ]
