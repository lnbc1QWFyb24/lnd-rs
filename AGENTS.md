## Commands

Run these command after making code changes and fix any errors or warnings before completing.

- `cargo check --all-targets` (errors)
- `cargo clippy --workspace --all-targets --all-features -- -W clippy::all -W clippy::pedantic` (linting)
- `cargo nextest run --all-features` (tests)
- `cargo fmt` (formatting)

## Documentation

- Use Rust doc comments (`///`) for every public item and for internal elements with nontrivial behavior.
  Describe:
  - Purpose and intent of the function, type, or module.
  - Parameters, return values, invariants, and side effects.
  - Rationale behind key logic or algorithmic choices when non-obvious.
- Write documentation incrementally during implementation; avoid retroactive bulk writing.
- Include usage examples demonstrating idiomatic and edge-case use. Favor executable code examples where possible (`#[doc = include_str!]` or doctests).
- Maintain a `docs/` directory within each crate for higher-level explanations: architecture overviews, module relations, and developer guides.
- Treat documentation as part of the interface contract—keep it synchronized with code and update immediately upon behavioral change.

## File Size

Aim to keep files less than ~300 lines where possible.
Keep each file small and tightly scoped. Avoid bloated, multi-purpose files.
When a file grows too large or mixes unrelated concerns, split it into smaller, focused files with clear boundaries.

## Async first

We use the `tokio` async environment. We need to be careful not to block the main thread with long running or tasks with heavy computation. Try to use the tokio async compatible version of methods and dependencies where possible. If you must use a blocking heavy call, then wrap it in a `spawn_blocking` call to ensure we do not block the main thread.

## Assertions

1. Purpose
   Assertions detect programmer errors and enforce invariants that must never be violated. They convert correctness failures into immediate crashes rather than silent corruption. Operational errors must be handled explicitly; assertions must never substitute for error handling.

2. Assertion Types and Scope

- **`debug_assert!`** — For internal developer invariants, non-critical or expensive checks, and verifying algorithmic properties in debug builds. Never used for input validation or memory safety.
- **`assert!`** — For invariants whose violation indicates logical impossibility or unsoundness under safe Rust semantics. Remains active in all builds.
- Assertions must never compensate for missing type modeling. Prefer encoding invariants in the type system first (`NonZero*`, newtypes, enums, smart constructors, `Option`/`Result`).

3. Type-Level Enforcement

Types define structure; assertions enforce semantics.
Model all constraints that can be represented statically—ownership, lifetimes, bounds, exclusivity—before asserting dynamically.
Assertions serve only to verify semantic relationships not capturable by types (e.g., ordering, cross-field consistency, arithmetic relationships).

4. Unsafe Boundaries

Inside `unsafe` blocks or FFI boundaries, place minimal constant-time runtime checks guarding all assumptions that the compiler cannot verify.
Supplement with `debug_assert!` for deeper invariants and range verification in debug builds.
Unsafe code must never rely solely on debug-only checks.

5. External Data and Configuration

All untrusted or external inputs (I/O, serialization, network, FFI) must be validated in every build configuration using type-checked `Result`/`Option` handling.
Assertions are reserved for invariants that, if violated, indicate an internal logic error—not user input failure.

6. Diagnostic and Build Control

Heavy validation, cross-checking, or structural audits belong behind `cfg!(debug_assertions)` or feature flags.
Release builds must retain only essential safety and soundness guards. Assertions in release paths must remain deterministic and cheap.

7. Density and Applicability

Every function must cover its invariants: arguments, return values, and key pre/post-conditions.
Average target: approximately two assertions per function _where meaningful_.
Do not assert for type-guaranteed or impossible conditions. Assertion count is a proxy for invariant clarity, not a quota.

8. Redundant Verification
   Validate critical properties across at least two independent code paths (e.g., before write and after read).

9. Documentation via Assertions
   Replace critical comments with self-evident `assert!` conditions. Assertions document expectations in executable form.

10. Atomic Assertions
    Use separate simple assertions (`assert(a); assert(b);`) instead of compound ones (`assert(a && b);`) for clarity and precise failure localization.

11. Implication Form
    Encode dependent conditions as `if (a) assert(b);` for explicit logical relationships.

12. Compile-Time Assertions
    Enforce constant relationships, invariants, and type-size constraints with compile-time checks to catch design errors before execution.

13. Positive and Negative Space
    Assert both valid and invalid boundaries. Test with both conforming and violating inputs to expose boundary fragility.

14. Failure Behavior
    When a runtime assertion fails in release, log concise contextual data and abort immediately. Continuing execution after a violated invariant is prohibited.

15. Discipline
    Assertions are a tool for understanding, not a replacement for it. Maintain a mental model of invariants and encode it in assertions.

## Ignore

- target/, Cargo.lock

## Rust Patterns & Functional Style Cheatsheet

### 0) Functional Core, Imperative Shell

Keep domain logic **pure**; push I/O, time, randomness to the edges.

### 1) TDD & Testability (first-class)

- We practice TDD. Write failing tests from the specs and test vectors, then implement code to pass them.
- Spec-driven tests first: derive cases from spec test vectors & invariants.
- Interfaces easy to test: design with DI (traits), no globals/singletons.
- In-memory/ephemeral adapters: provide in-memory DB/clock/queue for tests.
- Fakes over mocks: simple in-memory fakes implementing the same trait.
- Deterministic inputs: fixed seeds, fixed clocks, canonical sort orders.
- Fast tests: pure unit tests dominate; integration tests compose fakes/adapters.

TDD loop (short):

1. Add/extend spec test vector
2. Write failing unit test
3. Implement minimal code
4. Refactor

Guard with property tests if invariant-like

### 2) Error Handling (no panics in lib code except for assertions)

Return Result<T, E>; model domain errors with thiserror; avoid unwrap/expect in libraries.

### 3) Data Ownership & Borrowing

Prefer &str/&[T]/iterators; return owned results at API boundaries when ergonomic.

### 4) Traits > Macros for Abstraction

Use traits + generics for replaceable behavior (repos, clocks, rng, network).

### 5) Feature-Gated Heavy Deps (opt-in)

Users must be able to exclude heavy deps.

Cargo.toml

```toml
[features]
default = []
serde = ["dep:serde"]
chrono = ["dep:chrono"]
tracing = ["dep:tracing"]

[dependencies]
serde  = { version = "1", optional = true, features = ["derive"] }
chrono = { version = "0.4", optional = true, default-features = false, features = ["clock"] }
tracing = { version = "0.1", optional = true }
```

Conditional derives

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelId(pub [u8; 32]);
```

### 6) API Shapes That Compose

Accept iterators/slices; return iterators/collections. Use small parameter structs for complex fns.

```rust
pub struct ClassifyOpts {
    pub policy: Policy,
    pub fee_floor_sats: u64,
}

pub fn classify<'a, I>(txs: I, opts: &ClassifyOpts) -> Vec<LedgerEntry>
where
    I: IntoIterator<Item = &'a Tx>,
{
    txs.into_iter().flat_map(|tx| classify_one(tx, opts)).collect()
}
```

### 7) Testing Strategy (expanded)

- Unit tests (pure): exhaustive transforms; zero I/O.
- Property tests: proptest on invariants (balances, monotonicity).
- Golden vectors: live in the blueprint folder; mirrored in tests.
- Integration tests: compose adapters (use in-memory by default).
- Fixtures: builder helpers to create valid domain objects succinctly.
- No logging in pure functions; add tracing only in edge orchestration.

### 8) Time & Randomness

Inject via traits; never call Utc::now() or thread_rng() inside core logic.

```rust
pub trait Clock { fn now(&self) -> chrono::DateTime<chrono::Utc>; }
```
