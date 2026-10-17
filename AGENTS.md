# Project Guidance

- Use idiomatic Rust 2024; keep changes focused and lines under 80 columns
  when practical (120 maximum).
- DNS capture uses WinDivert on Windows for outbound, non-loopback IPv4 UDP/53
  only. Keep unmatched and unsupported packets fail-open; never change adapter
  DNS or resolver selection.
- Foreground capture is opt-in via `--run`. Service capture requires explicit
  Windows service installation; preserve service and tray behavior.
- The loopback dashboard is unauthenticated. Keep it loopback-only and retain
  request validation. TOML holds settings; rules are stored as JSON. Foreground
  rules are per-user, while service rules are shared under ProgramData.
- For Rust changes, run `cargo fmt --check`, `cargo check`, `cargo test`, and
  `cargo clippy --all-targets -- -D warnings` when applicable.
