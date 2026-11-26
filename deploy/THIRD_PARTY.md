# Installation bundle provenance

This is a private awg3-panel distribution. No production configuration, key,
password, hostname or GitHub credential is part of the build inputs.

- AmneziaWG Go: upstream amnezia-vpn/amneziawg-go, MIT; exact tag/commit in engine.lock.
  Protocol source is unchanged; security dependency overrides are pinned in
  deploy/enginebuild/go.mod and go.sum and recorded in BUILD_INFO.
- AmneziaWG tools / awg-quick: upstream amnezia-vpn/amneziawg-tools, GPL-2.0;
  exact corresponding source archive and COPYING accompany the binary.
- go-qrcode (MIT), yaml.v3 (MIT/Apache-2.0 as stated by its LICENSE),
  golang.org/x/crypto (BSD): license texts accompany the private bundle.
  License/notice files of linked engine modules accompany the bundle alongside
  engine-modules.txt; Go and statically-linked musl notices are included too.
- CPS packet generators and host pools are derived from hoaxisr/awg-manager
  v2.20.6 and the payload layouts of Sketchystan1/payloadGen. Both MIT notices
  are included. The generator runs locally in the panel and carries no WARP
  account or endpoint scanning code.

Deployment ideas were studied in bivlked/amneziawg-installer,
alexsemenovru/awg-easy-3 and wg-easy/wg-easy. Their application/installer code
was not copied. Upstream protocol tools are distributed as separate programs.

SHA256SUMS detects bundle corruption. Obtain the bundle over an authenticated
private repository connection and SCP; a checksum stored next to an archive
does not independently authenticate its publisher.
