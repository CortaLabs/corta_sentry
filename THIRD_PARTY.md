# Third-party software

CortaSentry directly depends on permissively licensed Go packages: google/uuid (BSD-3-Clause), the official Model Context Protocol Go SDK (MIT), Masterminds/semver (MIT), Prometheus client_golang (Apache-2.0), golang.org/x/time (BSD-3-Clause), gopkg.in/yaml.v3 (MIT/Apache-2.0 lineage), and modernc.org/sqlite (BSD-3-Clause, including SQLite public-domain code). The web build uses React/React DOM (MIT), Vite and its React plugin (MIT), TypeScript (Apache-2.0), and Vitest (MIT). Exact versions and transitive dependencies are pinned in `go.sum` and `web/package-lock.json`.

Nmap is not required, vendored, or redistributed. CortaSentry v0.1 imports Nmap XML but does not execute Nmap.
