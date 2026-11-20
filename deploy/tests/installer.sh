#!/usr/bin/env bash
# Fast launcher tests, only in an expendable Linux container.
set -euo pipefail
[[ -e /run/awg3panel-disposable-test ]] || { echo 'disposable marker required' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export DOWNLOAD="$work/download" RESULT="$work/result"
mkdir -p "$DOWNLOAD" "$work/bin" "$work/source/awg3panel-linux-amd64-test"
cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
url= out=
while (($#)); do case "$1" in --output) out=$2; shift 2;; https://*) url=$1; shift;; *) shift;; esac; done
cp "$DOWNLOAD/${url##*/}" "$out"
MOCK
chmod +x "$work/bin/curl"
export PATH="$work/bin:$PATH"
cat >"$work/source/awg3panel-linux-amd64-test/install.sh" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$RESULT"
MOCK
pack() {
 tar -czf "$DOWNLOAD/awg3panel-linux-amd64.tar.gz" -C "$work/source" awg3panel-linux-amd64-test
 (cd "$DOWNLOAD" && sha256sum awg3panel-linux-amd64.tar.gz > awg3panel-linux-amd64.tar.gz.sha256)
}
refuse() { rm -f "$RESULT"; if bash "$ROOT/install.sh" "$@" >"$work/log" 2>&1; then echo 'expected installer refusal' >&2; exit 1; fi; [[ ! -e "$RESULT" ]]; }
pack
bash "$ROOT/install.sh" --version v0.1.0 --dry-run --endpoint 203.0.113.10 --dns 1.1.1.1 >/dev/null
[[ $(cat "$RESULT") == $'--dry-run\n--endpoint\n203.0.113.10\n--dns\n1.1.1.1' ]]
refuse --version ../../evil --dry-run
printf corruption >> "$DOWNLOAD/awg3panel-linux-amd64.tar.gz"
refuse --dry-run
pack
printf '%064d  different.tar.gz\n' 0 > "$DOWNLOAD/awg3panel-linux-amd64.tar.gz.sha256"
refuse --dry-run
pack
ln -s /etc/passwd "$work/source/awg3panel-linux-amd64-test/unsafe"
pack
refuse --dry-run
rm "$work/source/awg3panel-linux-amd64-test/unsafe"
tar -czf "$DOWNLOAD/awg3panel-linux-amd64.tar.gz" --transform='s|awg3panel-linux-amd64-test|../escape|' -C "$work/source" awg3panel-linux-amd64-test
(cd "$DOWNLOAD" && sha256sum awg3panel-linux-amd64.tar.gz > awg3panel-linux-amd64.tar.gz.sha256)
refuse --dry-run
pack
bash "$ROOT/install.sh" --version v0.1.0 --endpoint 203.0.113.10 >/dev/null
bash "$ROOT/install.sh" --version v0.1.0 --endpoint 203.0.113.10 >/dev/null
[[ $(cat "$RESULT") == $'--endpoint\n203.0.113.10' ]]
cat >"$work/bin/mv" <<'MOCK'
#!/usr/bin/env bash
if [[ ${FAIL_CACHE_MOVE:-0} == 1 && ${!#} == */bundle ]]; then exit 42; fi
exec /bin/mv "$@"
MOCK
chmod +x "$work/bin/mv"
printf '\n# interrupted cache variant\n' >> "$work/source/awg3panel-linux-amd64-test/install.sh"
pack
if FAIL_CACHE_MOVE=1 bash "$ROOT/install.sh" --endpoint 203.0.113.10 >"$work/log" 2>&1; then echo 'fault not reached' >&2; exit 1; fi
bash "$ROOT/install.sh" --endpoint 203.0.113.10 >"$work/log" 2>&1
echo 'PASS: installer checksum, tar safety, options, cache repeat'
