# Project rules

- Keep generated keys, passwords, client profiles and operational host inventories out of Git, logs and issue reports.
- The daemon edits only peer sections. Preserve the server Interface bytes and apply mutations through snapshot, backup, atomic write, syncconf, postcondition and rollback.
- Never use setconf. Never print private keys or PSKs in errors.
- Root-only bootstrap may create a missing installation; it must not adopt or rewrite existing unmanaged configurations.
- Preserve automatic per-peer I1 generation and inherited protocol fields. Test full and readonly builds after application changes.
- Test installer changes on disposable Linux systemd/TUN fixtures, including conflicts, interruption, repeat, actual data transfer and rollback. Never use a working server as a test fixture.
- Read docs/install.md and docs/AI_AGENT_INSTALL.md before deployment. A green local health check does not prove provider or external-client reachability.
- Build releases from pinned dependencies using the workflow. Keep publication permissions limited to the release job.
