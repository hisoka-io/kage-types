# kage-types

Versioned Rust wire types shared by Kage services. This crate contains only serializable identifiers, API payloads, events, proof envelopes, registry profiles, and health responses.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
