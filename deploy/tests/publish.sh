#!/usr/bin/env bash
set -euo pipefail
[[ -e /run/awg3panel-disposable-test ]] || { echo 'disposable marker required' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/bin" "$work/dist"
export RESULT="$work/calls" TAG=v0.1.0 GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa GITHUB_REPOSITORY=example/lab
cat >"$work/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$RESULT"
case "$1 $2" in
 'release view') [[ "$FAKE_MODE" == existing-release ]]; exit $? ;;
 'release create') touch "$RESULT.published"; exit 0 ;;
 'api --method') [[ "$FAKE_MODE" != existing-tag && "$FAKE_MODE" != create-ref-fail ]]; exit $? ;;
 api*) [[ "$FAKE_MODE" == existing-tag ]]; exit $? ;;
 *) exit 9 ;;
esac
MOCK
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"
cd "$work"
printf 'bundle' >dist/awg3panel-linux-amd64.tar.gz
(cd dist && sha256sum awg3panel-linux-amd64.tar.gz >awg3panel-linux-amd64.tar.gz.sha256)
for mode in existing-release existing-tag create-ref-fail; do
  rm -f "$RESULT.published"
  if FAKE_MODE=$mode bash "$ROOT/deploy/publish-release.sh" >"$work/log" 2>&1; then echo "unsafe publication accepted: $mode" >&2; exit 1; fi
  [[ ! -e "$RESULT.published" ]]
done
FAKE_MODE=new bash "$ROOT/deploy/publish-release.sh" >"$work/log" 2>&1
[[ -e "$RESULT.published" ]]
grep -q 'api --method POST repos/example/lab/git/refs -f ref=refs/tags/v0.1.0 -f sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$RESULT"
grep -q 'release create v0.1.0 --verify-tag' "$RESULT"
echo 'PASS: release/tag immutability and atomic source binding'
