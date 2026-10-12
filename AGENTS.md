# Project Guidance

- Keep lines at or below 80 characters when practical; 120 is a hard limit.
- Use idiomatic Rust 2024 and keep changes focused in the relevant module.
- Preserve fail-open behavior: unmatched or unsupported DNS packets pass
  through unchanged. Do not change adapter DNS settings or resolver selection.
- Capture is opt-in via `--run`.
- For Rust changes, run `cargo fmt --check`, `cargo check`, `cargo test`, and
  `cargo clippy --all-targets -- -D warnings` when applicable.
