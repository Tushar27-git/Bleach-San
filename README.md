# BleachSan — High-Performance Windows Storage Cleaner

BleachSan is a fast, deterministic, and lightweight storage cleaner and disk analyzer for Windows 10 and 11, written in **Rust** and **Slint**.

## Features

- **Strict Safety Engine**: Fail-closed architecture. Protects Windows system files, user documents, and desktop files by default.
- **Deterministic Cleaning**: Cleans verified temporary and application caches without heuristics, registry hacking, or AI fluff.
- **Ultra-Minimalist UI**: Monochromatic, high-contrast, zero-gimmick Slint desktop interface.
- **Storage Analyzer**: Bounded parallel disk inspection to identify largest storage consumers.
- **Automation Ready**: Native Windows Task Scheduler integration for zero-resource daily maintenance (0% CPU and 0 RAM idle).
- **100% Local & Private**: Zero telemetry, zero analytics, zero network requests.

## Project Structure

```
crates/
├── cleaner-platform-windows/   # Direct Win32 / windows-rs bindings and OS primitives
├── cleaner-core/               # Safety engine, TOML rules, streaming scanner & executor
├── cleaner-ui/                 # Slint GUI frontend & viewmodels
└── cleaner-app/                # Combined Release CLI & GUI binary
```

## Building & Running

### Prerequisites
- Windows 10/11 x86-64
- Rust Stable (1.80+)

### Commands

```powershell
# Run interactive GUI
cargo run -p cleaner-app

# Headless Scan (stdout summary)
cargo run -p cleaner-app -- --scan

# Headless Scheduled Safe Clean (Task Scheduler mode)
cargo run -p cleaner-app -- --scheduled --clean-safe

# Storage Analyzer (Console mode)
cargo run -p cleaner-app -- --analyze

# Run all unit and integration tests
cargo test --workspace
```
