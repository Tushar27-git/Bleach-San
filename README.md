# BleachSan

BleachSan is a native, high-performance Windows storage cleaner and disk analyzer designed for speed, safety, and strict resource control. It is built in Rust and uses Slint for a lightweight graphical interface.

## Core Concepts & Architecture

The application is structured to provide deep disk analysis and cache cleaning while maintaining strict bounds on CPU and memory utilization.

### 1. Bounded Concurrency Engine
Traditional disk scanners either run strictly single-threaded (which is slow) or spawn unlimited threads (which saturates the CPU and starves other applications). BleachSan uses a bounded parallel orchestrator built on `rayon` and `jwalk`. The disk traversal engine is hard-capped to a strict 2-thread pool. This ensures that concurrent directory scanning operates fast enough to utilize SSD read speeds while physically preventing the application from exceeding low single-digit CPU usage (typically 3-5%) during heavy I/O operations.

### 2. Reparse Point Isolation
Scanning cloud-synchronized directories (such as OneDrive or Google Drive) often traps disk analyzers in loops, causing them to index hundreds of gigabytes of remote placeholders and spike CPU usage. BleachSan implements a custom pre-read filter at the Win32 filesystem level. It explicitly detects and blocks traversal into Windows Reparse Points and Junctions. This prevents the scanner from aggressively querying remote cloud files or falling into recursive directory structures.

### 3. Declarative Rule Engine
Rather than hardcoding file paths, BleachSan uses a deterministic, TOML-based rule engine. Cleaning definitions are separated from the core application logic. The engine parses these rules to locate temporary files, browser caches, and application logs using exact path resolution, environment variable expansion, and constrained deep searches. 

### 4. Fail-Closed Safety Model
The application enforces a strict safety boundary before any file deletion occurs. The safety validator intercepts all resolved paths and verifies them against a hardcoded list of protected root directories (e.g., `C:\Windows`, `C:\Users\Public`, or the root of any drive). If a rule attempts to traverse into a protected zone, the engine will fail closed and reject the operation, preventing accidental system damage.

## Tech Stack

- **Language**: Rust
- **User Interface**: Slint
- **Concurrency**: Rayon (Thread pooling), Crossbeam (Channel communication)
- **Filesystem Traversal**: jwalk
- **OS Bindings**: windows-rs (Direct Win32 API access)
- **Data Serialization**: Serde, toml

## Project Structure

- `crates/cleaner-platform-windows/`: Direct Win32 bindings and OS primitives (e.g., Reparse Point detection, Task Scheduler integration).
- `crates/cleaner-core/`: The backend engine containing the safety validator, TOML rule parser, and bounded streaming scanner.
- `crates/cleaner-ui/`: Slint frontend definitions and viewmodels.
- `crates/cleaner-app/`: Combined executable entry point.
- `rules/`: External TOML configurations defining cleanup targets for browsers and applications.

## Download & Installation

You can run BleachSan without needing to use the terminal or compile code:

1. **GitHub Releases:** Navigate to the [Releases](https://github.com/Tushar27-git/Bleach-San/releases) section of this repository and download the latest compiled executable.
2. **Direct Execution:** Alternatively, if you have downloaded or cloned the full repository, you can simply open the `target\release\` folder in Windows Explorer and double-click `bleachsan.exe` to launch the graphical interface directly.

## Building from Source

Ensure you have the Rust toolchain installed for Windows x86-64.

```powershell
# Build and run the graphical interface
cargo run -p cleaner-app --release

# Execute headless scanning from the command line
cargo run -p cleaner-app --release -- --scan

# Execute the storage analyzer via CLI
cargo run -p cleaner-app --release -- --analyze
```

## Testing

The core engine includes a comprehensive test suite to verify safety boundaries, rule resolution, and path traversal rejection.

```powershell
cargo test -p cleaner-core
```
