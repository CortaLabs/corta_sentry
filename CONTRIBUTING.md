# Contributing

By contributing, you agree that your work is licensed under MIT. Open an issue for large changes. Preserve the observation/interpretation boundary, fail-closed scope behavior, conservative identity rules, and uncertainty-aware findings.

Run `make lint test test-race build smoke`. Add regression tests for every scope, auth, identity, parser, and concurrency change. Tests must use loopback or mock services only. Never add exploit payloads, credential guessing, unsafe scanner arguments, outbound telemetry, or embedded secrets. Update `CHANGELOG.md` and relevant docs with user-visible behavior.
