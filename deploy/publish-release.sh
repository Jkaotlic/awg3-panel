#!/usr/bin/env bash
set -euo pipefail
: "${TAG:?release tag required}" "${GITHUB_SHA:?source commit required}" "${GITHUB_REPOSITORY:?repository required}"
export GH_REPO=$GITHUB_REPOSITORY
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ && "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid release tag or source commit' >&2; exit 1; }
(cd dist && sha256sum -c awg3panel-linux-amd64.tar.gz.sha256)
if gh release view "$TAG" >/dev/null 2>&1; then echo 'Release already exists; refusing replacement' >&2; exit 1; fi
if gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG" >/dev/null 2>&1; then echo 'Tag already exists; refusing replacement' >&2; exit 1; fi
# Exclusive ref creation also closes the check/create race with another run.
gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" -f "ref=refs/tags/$TAG" -f "sha=$GITHUB_SHA" >/dev/null
gh release create "$TAG" --verify-tag --title "$TAG" --notes-file docs/RELEASE_NOTES.md dist/awg3panel-linux-amd64.tar.gz dist/awg3panel-linux-amd64.tar.gz.sha256 dist/install.sh dist/BUILD_INFO
