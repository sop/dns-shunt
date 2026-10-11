# Project Guidance

- Keep lines at or below 80 characters when practical; 120 is a hard limit.
- Use idiomatic Rust 2024 and keep changes focused in the relevant module.
- Preserve fail-open behavior: unmatched or unsupported DNS packets pass
  through unchanged. Do not change adapter DNS settings or resolver selection.
- Capture is opt-in via `--run`. Treat WFP as experimental; driver changes
  require validation in a disposable Windows test VM.
- For Rust changes, run `cargo fmt --check`, `cargo check`, `cargo test`, and
  `cargo clippy --all-targets -- -D warnings` when applicable.
- Rust tests do not establish WFP driver safety. Driver builds require the
  Windows Driver Kit; follow the README's test-environment precautions.
