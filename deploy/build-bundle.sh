#!/usr/bin/env bash
# Run on a Linux build host (or deploy/Dockerfile.build). Never run on the VPS.
set -euo pipefail
export LC_ALL=C
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:-"$ROOT/dist"}
VERSION=${VERSION:-dev}
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux amd64 builder required' >&2; exit 1; }
[[ "$VERSION" =~ ^[a-zA-Z0-9._+-]+$ ]] || { echo 'invalid version' >&2; exit 1; }
for c in go curl sha256sum tar make musl-gcc python3; do command -v "$c" >/dev/null || { echo "missing build tool: $c" >&2; exit 1; }; done
source "$ROOT/deploy/engine.lock"
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
BUNDLE="$WORK/awg3panel-linux-amd64-$VERSION"
mkdir -p "$BUNDLE/bin" "$BUNDLE/deploy" "$BUNDLE/licenses" "$BUNDLE/docs" "$OUT"
for name in install.md AI_AGENT_INSTALL.md install-verification.md keenetic-junktune.md; do
  install -m 0644 "$ROOT/docs/$name" "$BUNDLE/docs/$name"
done
for item in go tools; do
  if [[ "$item" == go ]]; then repo=amneziawg-go; commit=$AWG_GO_COMMIT; hash=$AWG_GO_SHA256; else repo=amneziawg-tools; commit=$AWG_TOOLS_COMMIT; hash=$AWG_TOOLS_SHA256; fi
  curl -fsSL --retry 3 "https://codeload.github.com/amnezia-vpn/$repo/tar.gz/$commit" -o "$WORK/$item.tar.gz"
  printf '%s  %s\n' "$hash" "$WORK/$item.tar.gz" | sha256sum -c - >/dev/null
  tar -xzf "$WORK/$item.tar.gz" -C "$WORK"
done
cd "$ROOT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$BUNDLE/bin/awg3panel" ./cmd/awg3panel
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -tags readonly -ldflags "-s -w -X main.version=$VERSION" -o "$BUNDLE/bin/awg3panel-readonly" ./cmd/awg3panel
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$BUNDLE/bin/awg3setup" ./cmd/awg3setup
# Module builds retain the real upstream version in Go buildinfo, unlike a
# tarball build whose --version banner is an old upstream constant.
mkdir -p "$WORK/engine-build"
cp "$ROOT/deploy/enginebuild/go.mod" "$ROOT/deploy/enginebuild/go.sum" "$WORK/engine-build/"
cd "$WORK/engine-build"
go mod download -json "github.com/amnezia-vpn/amneziawg-go/v3@$AWG_GO_VERSION" > engine-origin.json
python3 - "$AWG_GO_COMMIT" < /dev/null <<'PY'
import json, sys
d=json.load(open('engine-origin.json'))
if d.get('Origin',{}).get('Hash') != sys.argv[1]:
    raise SystemExit('upstream module origin does not match engine.lock')
PY
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -trimpath -ldflags '-s -w' -o "$BUNDLE/bin/amneziawg-go" github.com/amnezia-vpn/amneziawg-go/v3
go list -mod=readonly -deps -json github.com/amnezia-vpn/amneziawg-go/v3 > "$WORK/engine-deps.json"
python3 - "$WORK/engine-deps.json" "$BUNDLE/licenses" <<'PY'
import hashlib,json,pathlib,shutil,sys
text=pathlib.Path(sys.argv[1]).read_text(); decoder=json.JSONDecoder(); modules={}
while text.strip():
    data,end=decoder.raw_decode(text.lstrip());text=text.lstrip()[end:]
    mod=data.get('Module',{})
    if mod.get('Dir'): modules[mod['Path']]=mod
out=pathlib.Path(sys.argv[2]);index=[]
for name,mod in sorted(modules.items()):
    source=pathlib.Path(mod['Dir'])
    notices=[p for p in source.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','LICENCE','COPYING','COPYRIGHT','NOTICE'))]
    if not notices: raise SystemExit('no license found for linked engine module: '+name)
    prefix=hashlib.sha256(name.encode()).hexdigest()[:12]
    for p in notices: shutil.copyfile(p,out/('engine-'+prefix+'-'+p.name))
    index.append(name+' '+mod.get('Version','source-pin'))
(out/'engine-modules.txt').write_text('\n'.join(index)+'\n')
PY
make -C "$WORK/amneziawg-tools-$AWG_TOOLS_COMMIT/src" -j2 CC=musl-gcc LDFLAGS=-static WITH_WGQUICK=yes
install -m 0755 "$WORK/amneziawg-tools-$AWG_TOOLS_COMMIT/src/wg" "$BUNDLE/bin/awg"
install -m 0755 "$WORK/amneziawg-tools-$AWG_TOOLS_COMMIT/src/wg-quick/linux.bash" "$BUNDLE/bin/awg-quick"
for name in bootstrap.sh awgtop-runtime.sh preflight.sh doctor.sh rollback.sh awgtop.service awg3panel.service engine.lock THIRD_PARTY.md; do install -m 0644 "$ROOT/deploy/$name" "$BUNDLE/deploy/$name"; done
install -m 0755 "$ROOT/deploy/keenetic-tune-bridge.py" "$BUNDLE/deploy/keenetic-tune-bridge.py"
mkdir -p "$BUNDLE/deploy/enginebuild"
cp "$ROOT/deploy/enginebuild/go.mod" "$ROOT/deploy/enginebuild/go.sum" "$BUNDLE/deploy/enginebuild/"
chmod 0755 "$BUNDLE/deploy/"*.sh
printf '#!/usr/bin/env bash\nset -euo pipefail\nexec bash "$(dirname -- "${BASH_SOURCE[0]}")/deploy/bootstrap.sh" "$@"\n' > "$BUNDLE/install.sh"
chmod 0755 "$BUNDLE/install.sh"
cp "$WORK/amneziawg-go-$AWG_GO_COMMIT/LICENSE" "$BUNDLE/licenses/amneziawg-go.txt"
cp "$WORK/amneziawg-tools-$AWG_TOOLS_COMMIT/COPYING" "$BUNDLE/licenses/amneziawg-tools.txt"
# GPL tools travel with their exact corresponding source, not just a URL.
cp "$WORK/tools.tar.gz" "$BUNDLE/licenses/amneziawg-tools-source.tar.gz"
cp "$(go env GOROOT)/LICENSE" "$BUNDLE/licenses/go.txt"
cp /usr/share/doc/musl/copyright "$BUNDLE/licenses/musl.txt"
for spec in 'github.com/skip2/go-qrcode LICENSE qrcode' 'gopkg.in/yaml.v3 LICENSE yaml' 'golang.org/x/crypto LICENSE xcrypto'; do read -r dir license name <<< "$spec"; cp "$ROOT/vendor/$dir/$license" "$BUNDLE/licenses/$name.txt"; done
printf 'panel_version=%s\ngo_toolchain=%s\nengine_version=%s\nengine_commit=%s\ntools_version=%s\ntools_commit=%s\npreset=personal-stun-v1\n' "$VERSION" "$(go version)" "$AWG_GO_VERSION" "$AWG_GO_COMMIT" "$AWG_TOOLS_VERSION" "$AWG_TOOLS_COMMIT" > "$BUNDLE/BUILD_INFO"
go list -m golang.org/x/crypto golang.org/x/net golang.org/x/sys >> "$BUNDLE/BUILD_INFO"
cp "$ROOT/deploy/THIRD_PARTY.md" "$BUNDLE/licenses/NOTICE.txt"
install -m 0644 "$ROOT/internal/warpsignature/LICENSE.awg-manager" "$BUNDLE/licenses/awg-manager.txt"
install -m 0644 "$ROOT/internal/warpsignature/LICENSE.payloadGen" "$BUNDLE/licenses/payloadGen.txt"
GOBIN="$WORK/checks" go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
for name in awg3panel awg3panel-readonly awg3setup amneziawg-go; do
  "$WORK/checks/govulncheck" -mode binary "$BUNDLE/bin/$name"
done
(cd "$BUNDLE" && find . -type f -printf '%P\n' | LC_ALL=C sort | while IFS= read -r f; do sha256sum "$f"; done) > "$WORK/SHA256SUMS"
mv "$WORK/SHA256SUMS" "$BUNDLE/SHA256SUMS"
tar -C "$WORK" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -czf "$OUT/$(basename "$BUNDLE").tar.gz" "$(basename "$BUNDLE")"
(cd "$OUT" && sha256sum "$(basename "$BUNDLE").tar.gz") > "$OUT/$(basename "$BUNDLE").tar.gz.sha256"
printf 'Bundle ready: %s\n' "$OUT/$(basename "$BUNDLE").tar.gz"
