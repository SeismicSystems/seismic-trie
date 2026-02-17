# Seismic Trie (alloy-trie)

Fork of [alloy-rs/trie](https://github.com/alloy-rs/trie) that extends the Merkle-Patricia Trie with **private/flagged storage** support. Standard MPT leaf nodes are extended with an `is_private` flag, causing the trie root and proofs to differ for private vs public state. Upstream is tracked through the `main` branch.

## What This Does

Ethereum's MPT is used to compute state roots and generate Merkle proofs. This fork adds:

- **Private leaf nodes** — `LeafNode` carries an `is_private: bool` flag, encoded via bit 6 of the first nibble byte: public `0x20`/`0x30` vs private `0x60`/`0x70` (see encoding details below)
- **Flagged storage integration** — uses `FlaggedStorage<V>` from the Seismic fork of `alloy-primitives` to pair values with privacy flags
- **Privacy-aware proof verification** — `verify_proof()` handles private nodes during inclusion and exclusion proofs
- **Privacy-aware hash building** — `HashBuilder` tracks `is_private` per leaf, producing different roots when privacy flags change

## Build

Rust crate using Cargo. MSRV: **1.85**. Uses a patched `alloy-primitives` from the Seismic fork (resolved automatically via `[patch.crates-io]` in Cargo.toml).

### macOS (arm64/x86_64)

```bash
# Prerequisites: Rust toolchain (rustup.rs)
rustup toolchain install stable  # or 1.85+

# Build
cargo build
```

### Linux (Ubuntu)

```bash
# Prerequisites
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install stable

# Build
cargo build
```

## Test

### All tests (default features — 29 tests)

```bash
cargo test
```

### All tests including property-based tests (39 tests)

```bash
cargo test --all-features
```

This enables the `arbitrary` feature which adds `proptest`-based tests for:

- Deterministic roots
- Privacy flag changing roots
- Privacy transitions changing roots
- Mixed-privacy proof verification
- Arbitrary hashed root / proof verification

### Lint checks (matches CI)

```bash
RUSTFLAGS="-D warnings" cargo check
cargo clippy
```

### Formatting (requires nightly for full config)

```bash
cargo +nightly fmt --check
```

On stable, `cargo fmt --check` works but emits warnings about nightly-only options.

### no_std compatibility check

```bash
cargo check --no-default-features
```

Do **not** run `cargo test --no-default-features` — test code uses `println!` which requires `std`.

### Benchmarks

```bash
cargo bench --bench bench --features arbitrary
```

Benchmarks nibble path encoding performance using `criterion`.

## Project Layout

```
src/
├── lib.rs                  Library root, defines EMPTY_ROOT_HASH
├── account.rs              TrieAccount (nonce, balance, storage_root, code_hash)
├── mask.rs                 TrieMask — 16-bit bitmask for branch child presence
├── root.rs                 Ordered trie root computation (receipt/state roots)
├── hash_builder/
│   ├── mod.rs              HashBuilder<K> — core incremental MPT root computation
│   └── value.rs            HashBuilderValue — value representation during hashing
├── nodes/
│   ├── mod.rs              TrieNode enum, encode_path_leaf/extension helpers
│   ├── branch.rs           BranchNode, BranchNodeCompact, BranchNodeRef
│   ├── extension.rs        ExtensionNode, ExtensionNodeRef
│   ├── leaf.rs             LeafNode with is_private flag (Seismic extension)
│   └── rlp.rs              RlpNode wrapper
└── proof/
    ├── mod.rs              Module exports
    ├── verify.rs           verify_proof() with private node handling
    ├── retainer.rs         ProofRetainer — captures proof nodes during hashing
    ├── decoded_retainer.rs DecodedProofRetainer
    ├── proof_nodes.rs      ProofNodes collection
    ├── decoded_proof_nodes.rs  DecodedProofNodes for verifiable proofs
    ├── added_removed_keys.rs   Key tracking in proofs
    └── error.rs            ProofVerificationError enum
```

## Key Seismic Modifications

Privacy support is threaded through the entire trie: leaf encoding → hash building → proof verification → storage root computation.

### Leaf encoding (`src/nodes/leaf.rs`, `src/nodes/mod.rs`)

`LeafNode` has an `is_private: bool` field. The privacy flag is encoded in the first nibble byte using bit layout `0bPLOx_xxxx`:
- **P** (bit 6) = private flag
- **L** (bit 5) = leaf flag (always 1 for leaves)
- **O** (bit 4) = odd nibble count

Four constants on `LeafNode`:
| Constant | Value | Meaning |
|---|---|---|
| `PUB_EVEN_FLAG` | `0x20` | Public leaf, even nibbles |
| `PUB_ODD_FLAG` | `0x30` | Public leaf, odd nibbles |
| `PRIV_EVEN_FLAG` | `0x60` | Private leaf, even nibbles |
| `PRIV_ODD_FLAG` | `0x70` | Private leaf, odd nibbles |

Private differs from public by exactly bit 6 (`0x40`). Extension nodes use `0x00`/`0x10` (unchanged from upstream).

`encode_path_leaf(nibbles, is_leaf, is_private)` — third parameter is new. **Panics** if `is_private=true` for extension nodes.

### Hash building (`src/hash_builder/mod.rs`)

- `HashBuilder` has a new `is_private: Option<bool>` field tracking the current leaf's flag
- `add_leaf(key, value, is_private)` — third parameter is new
- The privacy flag flows into `LeafNodeRef` construction during hashing, so different `is_private` values produce different trie roots even for identical key/value data

### Proof verification (`src/proof/verify.rs`, `src/proof/error.rs`)

- `verify_proof(root, key, expected_value, expected_is_private, proof)` — fourth parameter is new
- Tracks `last_decoded_node_is_private` through proof traversal
- Final check validates both value **and** privacy flag match
- `ProofVerificationError::ValueMismatch` now includes `got_private: bool` and `expected_private: bool` fields

### Storage root functions (`src/root.rs`)

- `storage_root()`, `storage_root_unhashed()`, `storage_root_unsorted()` now accept `T: Into<FlaggedStorage>` (from seismic-alloy-core) and extract `.value` and `.is_private()` to pass through to `add_leaf()`
- `state_root()` always uses `is_private = false` — account nodes are always public

### Important invariants

- **Extension nodes are always public** — `encode_path_leaf` panics if private
- **Account nodes are always public** — `state_root()` hardcodes `is_private = false`
- **`ordered_trie_root()` doesn't support private nodes** — `src/root.rs:48` has `let is_private = false; // TODO: fix` (used for receipt roots, not state)

### Dependency patch (`Cargo.toml`)

- `[patch.crates-io]` points `alloy-primitives` to SeismicSystems fork of alloy-core
- `alloy-primitives` features include `"seismic"` which provides the `FlaggedStorage` type

## Code Style

Configured in `rustfmt.toml`, `clippy.toml`, and `Cargo.toml [lints]`:

- Max line width: **100** chars
- Imports: crate-level granularity, reordered
- Clippy: all warnings enabled, `missing-const-for-fn` and `result_large_err` allowed
- `unused-must-use` is **deny**, `rust-2018-idioms` is **deny**
- Full `rustfmt.toml` config requires nightly (`imports_granularity`, `wrap_comments`, etc.)

## Feature Flags

| Feature     | Description                                                         |
| ----------- | ------------------------------------------------------------------- |
| `default`   | `std` + `alloy-primitives/default`                                  |
| `std`       | Standard library support (enables `std` across all dependencies)    |
| `serde`     | Serialization support (propagates to all deps)                      |
| `arbitrary` | Property-based testing (`proptest`, `arbitrary`, `proptest-derive`) |
| `ethereum`  | Ethereum-specific re-exports (currently empty)                      |

## CI

GitHub Actions in `.github/workflows/`:

- **seismic.yml** (runs on `seismic` branch): `rustfmt` (nightly), `cargo build`, `RUSTFLAGS="-D warnings" cargo check`, `cargo test`
- **ci.yml** (upstream, runs on `main`): matrix across stable/beta/nightly/MSRV, feature powerset, miri, clippy, docs
- **no_std.yml** (upstream): `cargo check --target riscv32imac-unknown-none-elf --no-default-features`
- **bench.yml** (upstream): CodSpeed benchmarks

## Branches

- `seismic` — main branch (PR target)
- `main` — upstream Alloy tracking branch

## Troubleshooting

| Problem                                                                        | Fix                                                                                                                                                |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cargo test --no-default-features` fails with `cannot find macro println`      | Expected — test code uses `println!` which requires `std`. Use `cargo check --no-default-features` for no_std validation (matches CI).             |
| `cargo test` warning: `function build_trie_root is never used`                 | Harmless dead-code warning in test helper. Does not affect compilation or test results.                                                            |
| `cargo test --all-features` warning: `unused import: U256` in `src/root.rs:62` | Harmless — `U256` is imported but only used when `arbitrary` feature triggers certain test paths.                                                  |
| `cargo fmt --check` warns about unstable features on stable Rust               | Expected — `rustfmt.toml` uses nightly options (`imports_granularity`, `wrap_comments`). Use `cargo +nightly fmt --check` for full config.         |
| `cargo doc` warning: `bare URL` in lib.rs                                      | Cosmetic rustdoc warning about upstream URL format. Does not affect doc generation.                                                                |
| Build fails fetching `seismic-alloy-core.git`                                  | Ensure you have network access to GitHub. The `[patch.crates-io]` entry requires fetching the Seismic fork of alloy-primitives at a pinned commit. |
