# Rust Windows Cleaner — Technical Build Specification

## 0. Mission

Build a Windows-first, lightweight PC storage-cleaning and storage-management application.

Primary goals:

- Safely identify disposable cache/temp data.
- Show exactly what will be removed before destructive cleanup.
- Clean system, application, browser, and developer caches.
- Provide optional storage analysis and automation.
- Remain effectively idle when not working.
- Minimize CPU, RAM, disk I/O, battery impact, and background activity.
- Prefer deterministic rules over heuristics or AI.
- Never delete unknown/user-critical data automatically.
- Use Rust as the production language.
- Python is development-only and must not be a runtime dependency.

Research references to study before implementation:
- BleachBit / CleanerML: https://github.com/bleachbit/cleanerml
- Slint desktop/Rust documentation: https://docs.slint.dev/
- Windows IFileOperation: https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-ifileoperation
- dua/pdu-style parallel filesystem analysis for performance ideas, but DO NOT copy their high-throughput behavior into background mode.

---

# 1. Product Principles

1. Fast when active, invisible when inactive.
2. Safety > cleanup quantity.
3. Unknown path = SKIP.
4. User data is protected by default.
5. No continuous full-disk scanning.
6. No continuous hashing.
7. No AI/LLM dependency.
8. No registry "cleaner".
9. No RAM booster/CPU booster gimmicks.
10. No kernel driver.
11. No shell-based deletion unless a Windows-specific operation absolutely requires it.
12. No unnecessary telemetry.
13. No unnecessary database in V1.
14. Do not run the entire UI elevated.
15. Do not build features that can silently execute arbitrary commands.
16. Every destructive action must originate from a validated CleanupPlan.

---

# 2. Target Platform

V1:
- Windows 10 x86-64
- Windows 11 x86-64

Future:
- Windows ARM64 if practical.

Use Rust stable and MSVC Windows toolchain.

---

# 3. Production Tech Stack

## Core
- Rust
- Cargo workspace

## GUI
- Slint
- Rust ↔ Slint integration
- Keep UI simple, native-feeling, non-AI, low-animation.

## Windows
- windows-rs
- Win32 APIs
- COM where appropriate
- Windows filesystem APIs
- Windows process APIs
- Windows Task Scheduler integration

## Serialization/configuration
- serde
- TOML for cleaner definitions
- Small local config files
- No SQLite initially

## Concurrency
- std threads / scoped threads where sufficient
- Rayon for bounded parallel filesystem analysis
- Tokio only where asynchronous services are genuinely useful
- Do not use async everywhere.

## Logging/errors
- tracing
- tracing-subscriber
- thiserror for typed library errors
- anyhow at application boundaries

## Testing
- Rust unit tests
- Rust integration tests
- temporary filesystem fixtures
- property/fuzz testing for path/rule parsing where useful

## Development-only
- Python scripts for rule generation, test data, benchmarking, research automation.
- Python must not be required to run the released application.

---

# 4. Repository Architecture

Use a Cargo workspace similar to:

cleaner/
├── Cargo.toml
├── crates/
│   ├── core/
│   │   ├── scanner/
│   │   ├── cleaner/
│   │   ├── rules/
│   │   ├── safety/
│   │   ├── storage/
│   │   ├── processes/
│   │   └── scheduler/
│   │
│   ├── platform-windows/
│   │   ├── filesystem/
│   │   ├── process/
│   │   ├── recycle_bin/
│   │   ├── elevation/
│   │   └── task_scheduler/
│   │
│   ├── ui/
│   │   ├── pages/
│   │   ├── components/
│   │   └── assets/
│   │
│   └── app/
│
├── rules/
│   ├── system/
│   ├── applications/
│   ├── browsers/
│   └── developer/
│
├── tests/
├── benchmarks/
├── scripts/
│   └── python/
├── docs/
└── .github/

Keep platform-specific code isolated from portable core logic.

---

# 5. Core Architecture

Main flow:

UI
 ↓
Application API
 ↓
Core
 ├── Rule Engine
 ├── Scan Engine
 ├── Safety Engine
 ├── Cleanup Engine
 ├── Storage Engine
 ├── Process Detector
 └── Scheduler
 ↓
Windows Platform Layer

The UI must never directly perform filesystem deletion.

The UI asks the core for:
- scan results
- cleanup plans
- cleanup execution
- progress
- errors
- statistics

---

# 6. Cleaner Rule Engine

Cleaner definitions must be separate from the Rust cleaning engine.

Concept:

Rule
 ↓
Resolve environment variables
 ↓
Validate target
 ↓
Check application/process state
 ↓
Safety classification
 ↓
Scan
 ↓
Create CleanupPlan
 ↓
Preview
 ↓
User/automation approval
 ↓
Execute

Use TOML initially.

Example:

```toml
id = "spotify"
name = "Spotify"
category = "application_cache"

[[targets]]
path = "%LOCALAPPDATA%/Spotify/Cache"
action = "delete_contents"

[[targets]]
path = "%LOCALAPPDATA%/Spotify/Code Cache"
action = "delete_contents"

[requirements]
process_closed = true
process_name = "Spotify.exe"
```

Rule schema must support at minimum:
- id
- display name
- category
- target path
- target type
- cleanup action
- process requirements
- safety level
- optional conditions
- documentation/source
- test metadata

Do not permit rules to execute arbitrary shell commands.

---

# 7. Safety Model

Define explicit safety levels:

SAFE:
- known temporary files
- known application caches
- browser caches
- shader caches
- known crash dumps
- disposable logs
- recycle bin
- known package-manager caches

REVIEW:
- node_modules
- old installers
- build artifacts
- large logs with uncertain use
- developer directories
- potentially recoverable files

USER_DATA:
- Downloads
- Desktop
- Documents
- Pictures
- Videos
- Music
- projects
- game saves
- unknown files

PROTECTED:
- Windows system files
- boot files
- registry hives
- Program Files
- system configuration
- unknown system directories
- application databases unless explicitly supported
- user profile roots

Default rule:
UNKNOWN = SKIP.

Never make deletion decisions based only on filename patterns such as "*.tmp" without a validated target context.

---

# 8. Path Safety

Every target must pass:

1. Environment-variable resolution.
2. Absolute-path resolution.
3. Canonicalization where safe.
4. Allowed-root validation.
5. Symlink/junction protection.
6. Rule-specific target validation.
7. Safety classification.

Default:
- Do not follow symlinks.
- Treat Windows junctions/mount points carefully.
- Prevent path traversal.
- Prevent a rule from escaping its intended root.
- Never allow arbitrary user-supplied paths to become automatic cleanup targets without explicit review.

---

# 9. Scan Engine

V1 must focus on direct known paths.

Do NOT scan the whole C: drive for every cleanup.

Known cleaner:
- resolve direct target
- enumerate relevant files/directories
- calculate size
- detect locked files
- detect permissions
- return results

Full disk analysis is a separate explicit user operation.

Scanner must support:
- cancellation
- progress
- bounded concurrency
- errors without crashing
- inaccessible paths
- locked files
- long paths
- Unicode paths
- symlinks/junctions
- permission failures

Use streaming aggregation instead of retaining millions of file objects in memory.

---

# 10. CleanupPlan

Never scan and immediately delete.

Required lifecycle:

Scan
 ↓
CleanupPlan
 ↓
Preview
 ↓
Approval
 ↓
Execute
 ↓
CleanupResult

CleanupPlan should contain:
- target
- action
- file count
- estimated bytes
- safety level
- process state
- warnings
- skipped items
- rule ID

CleanupResult should contain:
- files successfully removed
- files skipped
- files failed
- bytes reclaimed
- error categories
- duration

Deletion must be resilient:
- locked file = skip
- permission denied = report/skip
- missing file = treat as already cleaned
- unexpected error = report, do not crash entire operation

---

# 11. Windows File Operations

Prefer native Windows APIs over cmd.exe/PowerShell.

Study and use Windows IFileOperation where appropriate for Shell file operations, progress, and error reporting.

Do not use:
- `cmd /c del`
- `rmdir`
- arbitrary PowerShell deletion
- batch scripts

unless a specific Windows feature has no suitable native API and the operation is tightly controlled.

---

# 12. Process Detection

Cleaner rules may require an application to be closed.

Example:
Spotify.exe running
 ↓
Do not delete Spotify cache
 ↓
Show "Spotify is running"
 ↓
Offer skip/close-and-clean only if explicitly designed

Never forcibly terminate user applications by default.

Process detection should be cheap and only performed for relevant cleaners.

---

# 13. Initial Cleaners

V1 target categories:

## System
- User TEMP
- Windows TEMP where safely accessible
- known temporary files
- thumbnail cache where safe
- crash dumps where safe
- recycle bin

## Applications
- Spotify
- Chrome
- Edge
- Discord
- Steam
- VS Code

## Developer
- npm cache
- pnpm store/cache where safe
- pip cache
- Cargo cache

Rules must be verified against current application behavior before release.

Do not assume a path is safe merely because it appears online.

---

# 14. Developer Cleanup

Special handling:

npm cache:
SAFE if verified.

pip cache:
SAFE if verified.

Cargo cache:
SAFE only for explicitly disposable cache components.

node_modules:
REVIEW, never automatic by default.

Build directories:
REVIEW unless explicitly selected.

__pycache__:
Usually safe, but rule must be scoped.

Developer cleanup should show:
- project/path
- size
- last modified
- risk
- consequence of deletion

---

# 15. Storage Analyzer

Separate from normal cleanup.

User explicitly selects:
Storage → Analyze

Possible output:

C:\
 ├── Users
 ├── Windows
 ├── Program Files
 ├── Games
 ├── Developer
 └── Other

Show:
- used space
- free space
- largest directories
- largest files
- categories
- developer storage
- optional application storage

Do not continuously maintain a full-drive index in V1.

---

# 16. Storage Scanner Performance

Study high-performance Rust disk analyzers such as dua/pdu for:
- bounded parallelism
- work distribution
- filesystem traversal
- aggregation

Do NOT copy their "maximize disk throughput" behavior into background mode.

Modes:

LOW_IMPACT:
- minimal workers
- low I/O pressure
- background use

BALANCED:
- moderate workers
- manual normal scan

FAST:
- more workers
- user explicitly requested
- foreground only

Expose this internally first; UI exposure can be decided later.

---

# 17. Resource Budget

These are engineering targets and must be benchmarked.

Idle with app closed:
- 0 CPU
- 0 RAM

Optional background mode:
- target ≤ 30 MB RAM
- effectively 0% CPU while idle
- no continuous filesystem scan

Cleanup:
- target low CPU usage
- target ≤ 100 MB RAM

Storage analysis:
- target ≤ 200 MB RAM for normal operation
- temporary higher usage allowed only when justified

Avoid:
- unbounded vectors
- millions of file objects retained in memory
- continuous hashing
- polling every second
- background full-disk scanning
- unnecessary timers
- permanent scan indexes

---

# 18. Background Architecture

Preferred default:

Windows Task Scheduler
 ↓
launch cleaner CLI/task
 ↓
perform configured safe cleanup
 ↓
exit

Therefore:
- no persistent RAM usage
- no persistent CPU usage

Optional tray/background agent:
- Rust executable
- only if user enables it
- sleep/event-driven
- no continuous scanning
- no aggressive polling
- minimal memory footprint

The agent should mostly be asleep.

---

# 19. Automation

Support eventually:

- manual
- daily
- weekly
- monthly
- low disk space trigger

Example:

Free disk < 15%
 ↓
Run SAFE cleaners only
 ↓
Recalculate free space
 ↓
Notify user
 ↓
Exit

Never automatically run REVIEW cleaners unless the user explicitly configured that behavior.

---

# 20. UI

Use Slint.

UI principles:
- clean
- non-AI
- no gimmicky gradients
- no fake optimization scores
- minimal animations
- no unnecessary dashboards
- clear typography
- obvious Scan / Review / Clean flow
- accessible contrast
- responsive during scans

Pages:

1. Overview
2. Cleanup
3. Storage
4. Applications
5. Automation
6. Settings

Cleanup UI:

Category
 ↓
Cleaner
 ↓
Size
 ↓
Risk
 ↓
Details
 ↓
Selection
 ↓
Clean

Always show estimated reclaimable space before destructive cleanup.

---

# 21. Privilege/Elevation

Do not run the complete UI as Administrator.

Architecture:

Normal user GUI
 ↓
specific privileged operation
 ↓
small elevated helper / native elevation mechanism
 ↓
perform only authorized operation
 ↓
return result

Privileged interface must be narrow.

Never expose:
- arbitrary command execution
- arbitrary PowerShell
- arbitrary shell
- arbitrary path deletion without validation

---

# 22. Database

V1:
NO DATABASE.

Use:
- TOML configuration
- small JSON/state files if required

Consider SQLite only later for:
- cleanup history
- historical storage data
- large indexed metadata
- analytics

Do not introduce a database without a concrete requirement.

---

# 23. Logging

Use tracing.

Normal mode:
- minimal logs
- no constant disk writes

Debug mode:
- detailed logs

Rotate logs.

Never allow logs to grow indefinitely.

---

# 24. Privacy

V1:
- no telemetry
- no cloud dependency
- no account
- no analytics
- no external API requirement for cleaning

All scanning/cleanup should happen locally.

---

# 25. Testing Requirements

Every destructive component requires tests.

Unit tests:
- rule parsing
- environment resolution
- path validation
- safety classification
- cleanup planning
- process detection abstraction
- size aggregation

Integration tests:
- create temporary fake cache
- scan
- create plan
- preview
- execute
- verify deletion

Never run destructive tests against the real user C:\ drive.

Test:
- locked files
- permission denied
- missing files
- Unicode
- long paths
- junctions
- symlinks
- invalid rules
- malformed TOML
- path traversal attempts
- application currently running

Fuzz:
- rule parser
- path resolver
- cleaner target validation

---

# 26. Performance Testing

Create benchmarks for:

- startup time
- idle CPU
- idle RAM
- scan CPU
- scan RAM
- scan duration
- disk I/O
- cleanup speed
- UI responsiveness
- background wakeups

Set regression thresholds.

Example:
- idle CPU must remain effectively zero
- idle RAM should remain within target
- no unbounded memory growth during large scans
- background cleanup must not noticeably interfere with normal PC use

Benchmark on:
- SSD
- HDD if available
- low-RAM machine
- modern/high-end machine

---

# 27. Security Requirements

Mandatory:
- validate every cleaner target
- no arbitrary command execution
- no arbitrary shell execution
- no unsafe symlink following
- no path traversal
- no automatic user-data deletion
- least privilege
- narrow elevated operations
- signed release binaries when distribution begins
- verify update packages before installation
- fail closed when safety cannot be established

---

# 28. Development Phases

## Phase 0 — Research
Study:
- BleachBit
- CleanerML
- Windows Storage Sense
- Windows IFileOperation
- windows-rs
- Slint
- dua/pdu-style filesystem traversal

Do not copy proprietary code.

## Phase 1 — Core
Implement:
- data models
- rules
- scanner interfaces
- safety engine
- cleanup plan
- cleanup result

No UI.

## Phase 2 — Rule Engine
Implement TOML schema and initial cleaners.

## Phase 3 — Scanner
Implement safe direct-path scanning.

## Phase 4 — Cleanup
Implement preview + execution + error handling.

## Phase 5 — Windows
Implement native Windows integrations.

## Phase 6 — UI
Implement Slint frontend.

## Phase 7 — Performance
Benchmark and optimize resource usage.

## Phase 8 — Storage Analyzer
Implement explicit user-triggered disk analysis.

## Phase 9 — Automation
Implement Task Scheduler and optional low-resource agent.

## Phase 10 — Developer Cleanup
Expand npm/pnpm/pip/Cargo/build/node_modules handling.

## Phase 11 — Advanced
Later:
- incremental filesystem updates
- USN Journal
- duplicate detection
- partial/full hashing
- cleanup history
- plugin/rule ecosystem

---

# 29. V1 Scope

Must have:

- Rust core
- Slint UI
- TOML cleaner rules
- safety engine
- cleanup preview
- safe cleanup execution
- process detection
- system cleaners
- application cleaners
- developer cache cleaners
- robust errors
- low-resource behavior
- tests
- benchmarks

Do NOT include in V1:
- duplicate finder
- full-drive continuous indexing
- AI
- registry cleaning
- RAM boosting
- game boosting
- kernel driver
- telemetry
- cloud account
- complex database
- plugin marketplace

---

# 30. V2 Scope

- Storage analyzer
- largest files/folders
- developer storage analysis
- node_modules analysis
- automation
- low-disk trigger
- Task Scheduler integration
- optional tray agent
- richer application detection

---

# 31. V3 Scope

- incremental storage indexing
- NTFS USN Journal research/implementation
- duplicate detection
- staged hashing
- cleanup history
- advanced rule system
- rule/plugin ecosystem
- signed updates

---

# 32. Non-Negotiable Engineering Rules

1. Never delete unknown files.
2. Never trust a filename alone.
3. Never run arbitrary shell commands from cleaner rules.
4. Never run the GUI elevated by default.
5. Never continuously scan the entire disk.
6. Never poll aggressively.
7. Never retain huge file lists unnecessarily.
8. Never perform full-drive hashing in background.
9. Never make "optimization" claims that cannot be measured.
10. Never sacrifice safety for reclaimed-space numbers.
11. Never add a dependency without a reason.
12. Prefer standard library/native Windows APIs where sufficient.
13. Keep platform-specific code isolated.
14. Keep UI independent from cleanup logic.
15. Every cleanup operation must be represented as a validated plan before execution.
16. If uncertain, skip.
17. Benchmark every major performance change.
18. Background mode must be designed around sleeping/triggered execution.
19. Do not use Python as a runtime dependency.
20. Do not turn the application into a generic "PC optimizer."

---

# 33. Expected User Workflow

Normal manual cleanup:

Open app
 ↓
Overview
 ↓
Scan
 ↓
Scanner evaluates known rules
 ↓
Safety engine classifies candidates
 ↓
UI displays reclaimable space
 ↓
User reviews
 ↓
Create CleanupPlan
 ↓
Execute
 ↓
Show results
 ↓
Release memory/resources
 ↓
Return to idle

Background cleanup:

Windows Task Scheduler
 ↓
Launch lightweight cleanup process
 ↓
Load rules
 ↓
Check conditions
 ↓
Run SAFE cleaners
 ↓
Write minimal result
 ↓
Exit

Storage analysis:

User opens Storage
 ↓
Analyze
 ↓
Bounded/adaptive scan
 ↓
Aggregate sizes
 ↓
Display largest consumers
 ↓
Release scan resources
 ↓
Return to idle

---

# 34. Definition of "Good"

The application is successful only if it is:

- safe
- predictable
- transparent
- lightweight
- fast when actively used
- almost invisible when idle
- modular
- testable
- maintainable
- Windows-native where appropriate
- useful for developers
- extensible through cleaner rules
- not bloated with fake optimization features

Primary performance philosophy:

FAST WHEN ACTIVE.
INVISIBLE WHEN INACTIVE.
