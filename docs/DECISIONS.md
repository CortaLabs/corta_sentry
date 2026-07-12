# Engineering decisions

- Modular monolith: one deployable unit keeps transactions and operator experience simple while internal interfaces leave sensor/Council seams.
- SQLite WAL by default: offline, low-operation deployment with explicit SQL and migrations; no ORM hides identity or evidence semantics.
- Observation and interpretation separation: immutable facts survive improved rules; judgments can be recalculated.
- Deterministic rules: offline, explainable, testable, and incapable of remote code execution. No runtime LLM.
- Conservative identity: strong agreement can attach; weak evidence prefers duplicates over destructive false merges.
- No Council dependency: later orchestration consumes narrow services/events rather than redefining the domain.
- No exploit validation in v0.1: advisory correlation expresses uncertainty and cannot declare exploitability from family evidence.
