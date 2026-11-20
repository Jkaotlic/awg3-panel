# Project guide

Follow [AGENTS.md](AGENTS.md), [operator instructions](docs/install.md) and
[agent instructions](docs/AI_AGENT_INSTALL.md).

The daemon manages peers only. Server Interface editing and server lifecycle
changes belong to the separate root-only bootstrap, not to HTTP handlers.
Private keys and PSKs never belong in logs. Full and readonly builds must retain
their permission boundary. Keep private operational records outside this repository.
