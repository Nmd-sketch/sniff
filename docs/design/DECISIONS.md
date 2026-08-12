# Architecture Decision Log

This file records the significant architectural decisions, trade-offs, and dead-ends
we have made while building **sniff**, an `fd`-like file search tool for Windows.

Status legend:
- **Accepted** — the decision is in effect on `main`.
- **Superseded** — replaced by a later decision (kept for context).
- **Rejected** — considered and explicitly not chosen.

---

## ADR-001 — Layered architecture

- **Status:** Accepted

### Context
sniff started with two commits groping for a structure. We needed a shape that would
survive feature growth without entangling concerns (CLI parsing, orchestration, domain
logic, OS-level filesystem access).

### Decision
Split the code base into four layers living under `src/`, each a static library:

| Layer            | Responsibility                                             | May depend on        |
|------------------|------------------------------------------------------------|----------------------|
| `interface`      | CLI parsing, output formatting (`CliController`, formatters) | `application`        |
| `application`    | Use cases / orchestration (`SearchService`), DTOs, ports    | `domain`             |
| `domain`         | Pure logic: entry model, filters, matching, sorting          | nothing              |
| `infrastructure` | Concrete adapters (`Win32Scanner`)                          | `domain`             |

CMake linkage enforces the direction: `interface_layer PRIVATE application_layer`,
`application_layer PUBLIC domain_layer`, `infrastructure_layer PUBLIC domain_layer`.

### Trade-offs
- Clear dependency direction, isolated pure core → cheap and fast tests.
- Costs a bit of boilerplate and indirection for small features.

### Alternatives
- Single binary with everything in one translation unit — rejected (unmaintainable,
  contradicts the refactor history).
- Header-only interface — rejected, layer libraries keep rebuilds small.

---

## ADR-002 — Ports & adapters (hexagonal) for search

- **Status:** Accepted

### Context
`SearchService` must orchestrate filtering and sorting but must not know how entries are
produced (real filesystem in production, fakes in tests).

### Decision
Two explicit ports:

- **Primary port** `application/port/ISearchService.hpp` — what the CLI talks to.
- **Secondary port** `domain/ports/IEntryRepository.hpp` with a streaming sink:

  ```cpp
  using Sink = std::function<bool(std::unique_ptr<IEntry> entry, int depth)>;
  virtual void scan(const std::vector<std::string>& paths,
                    const FilterSpec& spec, const Sink& sink,
                    CancellationToken& token) const = 0;
  ```

  Returning `false` from the sink stops traversal (drives cancellation and early exit).
  The sink owns the entry and may drop it.

Infrastructure provides `Win32Scanner`; tests provide a `FakeEntryRepository`.

### Trade-offs
- Streams entries one at a time (no materialized in-memory tree) → low memory on huge
  directories; `SearchService` still collects matched entries, which results are sorted.
- Port API is coarse (`scan(...)`) but decoupling is worth it.

---

## ADR-003 — IEntry as a pure interface, results as plain DTOs

- **Status:** Accepted

### Context
An earlier brainstorm considered a composite `IEntry` (parent/children) with slicing-prone
value storage. We needed formatters, filters, and the CLI to consume results uniformly.

### Decision
- `domain::IEntry` is a small pure-virtual interface (name, path, type, hidden, executable,
  size, created, modified — **no children**).
- `domain::DomainEntry` is the concrete implementation (immutable value).
- Results travel as `std::vector<std::unique_ptr<IEntry>>` — slicing-safe and owning.
- `application::QueryResult` is a **plain DTO**: entries, `QueryResultStats`, `aborted`.
  The service never leaks internal types up to the CLI.

### Trade-offs
- `unique_ptr` means reallocation/ownership care; value semantics are lost.
- Keeps the "no composite model" honesty: tree rendering is a format concern that the
  `TreeFormatter` reconstructs by splitting paths — not the domain's problem.

---

## ADR-004 — Cancellation via a domain-level token + RAII signal handler

- **Status:** Accepted

### Context
Ctrl+C must stop a possibly long directory walk without leaving a half-built result printed
as success, and the mechanism must be usable by every layer.

### Decision
- `domain::model/CancellationToken.hpp` — a single `std::atomic<bool>` with
  `requestStop()` / `isStopped()` (relaxed ordering, trivially thread-safe).
  It lives in the **domain** so all layers can reference it without coupling.
- `application::SignalHandler` registers the OS handler (`SetConsoleCtrlHandler` on
  Windows, `sigaction` on POSIX) and flips the token; RAII unregisters on scope exit.
- `CliController` creates the token + handler around every `search` call.
- The scanner checks the token per entry; `SearchService` also checks it on the sink and
  between roots. A stopped scan returns `QueryResult{aborted = true}`.

### Trade-offs
- Cooperative polling (not preemption): worst case we finish the current entry. Fine for
  a filesystem walk and simpler than thread-based cancellation.

---

## ADR-005 — Search pipeline composition

- **Status:** Accepted

### Context
Filters (`name`, `extension`, `size`, `hidden`, `date`, `type`, `depth`, `exclude`) are
optional, combinable, and must be constructed from the CLI spec without the pipeline
caring about details.

### Decision
- `domain::FilterFactory::createChain(pattern, spec)` builds a `FilterChain` — an ordered
  list of `IFilter`s ANDed together.
- Every filter implements `bool matches(const IEntry&, int depth)`.
- `SearchService` builds the chain once, streams entries from the repository, counts
  stats, then sorts matches with `domain::Sorter` (case-insensitive path sort).

### Trade-offs
- Chain construction hides per-filter wiring; adding a filter means a new class + one
  factory branch.

---

## ADR-006 — Pattern language and matching modes

- **Status:** Accepted

### Context
`fd` defaults change behavior based on pattern style. We had to pick a sensible default
and be explicit about anchoring.

### Decision
Three match modes (`MatchMode`), chosen per run via flags; **default is REGEX**:

| Mode         | Flag            | Semantics                                  | Anchor?          |
|--------------|-----------------|--------------------------------------------|------------------|
| `REGEX`      | (default)       | `std::regex` search                        | unanchored       |
| `GLOB`       | `--glob` / `-g` | shell-style `*`, `?`, `[class]`            | anchored `^…$`   |
| `FIXED`      | `--fixed-strings` / `-F` | literal substring                    | unanchored       |

- `Matcher` translates globs to a regex (escaping specials, wrapping `^…$`) and catches
  `std::regex_error`, surfacing a clear "invalid pattern" message instead of a crash.
- `--case-sensitive`/`-s` vs `--ignore-case`/`-i` control `MatchMode`/`CaseMode` for the
  name (or full path with `--full-path`/`-p`).
- Matching target default: **file name**; `-p`/`--full-path` matches against the full path.

### Trade-offs
- Regex default is grep-like and powerful but a literal `*` alone is an error without
  `--glob` (documented; `sniff '*' … -g`).
- `fd`-style "smart casing" is not implemented; case is explicit.

---

## ADR-007 — Win32 scanner vs `std::filesystem`

- **Status:** Accepted

### Context
The tool must be fast on large trees and we wanted full control over entries (per-entry
metadata without extra stat calls).

### Decision
Implement `IEntryRepository` with the **Win32 directory API** (`FindFirstFileW` /
`FindNextFileW`) in `src/infrastructure/scanner/`:

- `WIN32_FIND_DATAW` gives attributes, size, created/modified times without extra
  `GetFileAttributes` calls.
- Wide (UTF-16) names converted to UTF-8 for the domain (`Win32ScanCore`).
- Split into a pure "core" (`Win32ScanCore`) — classification, conversions, path grammar,
  executable detection — unit-testable with synthetic records, and a traversal driver
  (`Win32Scanner`).

### Trade-offs
- Windows-only (guarded by `if(WIN32)` in CMake; POSIX builds get an empty lib). By
  design for now.
- More code and Win32 pitfalls than `std::filesystem`, but matches the performance goal
  and gives precise traversal hooks (depth pruning, symlink policy, cancellation).

### Alternatives
- `std::filesystem::recursive_directory_iterator` — **rejected**: per-entry
  `directory_entry` stat overhead, clunky depth/follow control, UTF-18 path handling
  still needed.

---

## ADR-008 — Path string format

- **Status:** Accepted

### Context
Entry paths reach the user via output formats and the `--full-path` matcher. Windows
native style uses backslashes; every other tool (and JSON consumers) expects `/`.

### Decision
- Paths are **relative**, **forward-slash** joined.
- A scan root of `.` normalizes to `""` (children print as `main.cpp`, not `./main.cpp`).
- Leading `./` on explicit roots (`./src`) is stripped.
- Root not-found semantics still reported with the *user's* spelling in the error.

### Trade-offs
- Loses the literal root the user typed; matches `fd` UX and keeps JSON/table output clean.

---

## ADR-009 — Executable detection on Windows (no exec bit)

- **Status:** Accepted

### Context
`IEntry::isExecutable()` feeds the `--type executable` filter, but Windows has no unix
permission bits; executability is a convention by extension (plus `PATHEXT`).

### Decision
- A curated default set: `.exe .com .bat .cmd .ps1 .msi .scr`, merged with entries from
  the `PATHEXT` environment variable (lowercased, normalized with a leading dot).
- Pure core function `hasExecutableExtension(ext, set)` is unit-tested; the set is read
  once per scan.

### Trade-offs
- Heuristic: a renamed script or a binary without an extension won't be flagged.
- Cheap and deterministic (no per-file syscall).

### Alternatives
- Real permission probing — **rejected** for now (backlogged). On Windows it would mean
  reading ACLs; not needed for an MVP.

---

## ADR-010 — Symlink / junction policy and cycle safety

- **Status:** Accepted

### Context
Windows distinguishes file vs directory symlinks and junctions; naive recursion can loop.

### Decision
- Any **reparse point** (`FILE_ATTRIBUTE_REPARSE_POINT`) is reported as
  `EntryType::SYMLINK` (junctions included) rather than resolving it to a directory.
- Traversal descends into reparse-point directories **only** when
  `FilterSpec::follow_symlinks` is set (`--follow`/`-L`).
- Cycle safety: when following, canonicalize each symlinked dir we open
  (`GetFinalPathNameByHandleW`) and keep a visited set. Crucially the set is recorded
  **only for symlinked directories** — recording physical dirs caused real dirs reached
  through both their physical path and a link to be skipped (a genuine bug found and
  fixed in the integration tests).

### Trade-offs
- With `--follow`, a dir plus a link pointing at it produces duplicate entries (both
  paths) but never a hang; that matches `fd -L` behavior.
- Junctions are treated as symlinks, which can surprise users who think of junctions as
  "real" dirs — accepted for uniformity.

---

## ADR-011 — Depth semantics and traversal pruning

- **Status:** Accepted

### Context
`--max-depth`/`--min-depth` must behave consistently between the domain filter and the
expensive filesystem walk.

### Decision
- Direct children of a scan root are at **depth 0**; each descent adds 1.
- **DepthFilter** (domain) applies `min_depth`/`max_depth` to every entry.
- **Scanner** additionally *prunes the walk* at `max_depth` (`descend` refuses to open a
  directory whose children would exceed it) purely for performance. `min_depth` is
  filter-only — we still walk to emit deeper entries.
- "No search pattern" is an error at the CLI layer; `SearchService` defaults paths to `.`
  when none are given.

### Trade-offs
- Pruning at the scanner duplicates part of the depth logic; the two must stay in sync
  (enforced by integration tests).

---

## ADR-012 — UTF-8 encoding and console output (two attempts)

- **Status:** Accepted (after a false start)

### Context
The default tree output used Unicode box-drawing glyphs (`├──`, `└──`, `│`). On the
default console codepage (e.g. `ibm437`) these rendered as mojibake (`ΓööΓöÇΓöÇ`).

### False start — ASCII fallback (Superseded)
We first replaced the glyphs with ASCII (`|--`, `\--`, `|`) to dodge encoding entirely.
That worked but looked poor and still left non-ASCII *filenames* mis-rendered — the
encoding problem, not the glyphs, was the true bug.

### Final decision
- Compile everything with **`/utf-8`** (source + execution charset = UTF-8), guaranteeing
  string literals in the binary are real UTF-8 bytes (`E2 94 9C` = `├`).
- At the start of `CliController::run`, on Windows: `SetConsoleOutputCP(CP_UTF8)` so the
  console decodes our UTF-8 output correctly.
- Investigatory note: the earlier "still corrupted with `/utf-8`" observation was an
  artifact of inspecting output through a PowerShell pipe that re-decoded bytes with the
  console codepage (and, in one try, of pointing at the wrong executable) — the emitted
  bytes were always correct with `/utf-8`. Measure raw bytes via `cmd /c … > file`
  redirection for reliable verification.

### Trade-offs
- Production output bytes are UTF-8; consumers of piped output should expect UTF-8
  (correct for files and UTF-8-aware tools).
- Legacy `conhost` (Windows < 10 console, cmd.exe in some hosts) can still render box
  glyphs imperfectly; Windows Terminal / modern conhost handle them. ASCII-safe for
  ASCII input otherwise.

---

## ADR-013 — Root path errors

- **Status:** Accepted

### Context
What happens when the user passes a non-existent or inaccessible scan root?

### Decision
- A missing/unreadable **root** throws `std::runtime_error("<path>: No such file or
  directory")`; `CliController` catches it, prints `sniff: …` to stderr, exits **1**
  (fd-like).
- Access-denied below the root (during recursion) is **silently skipped** — the walk
  continues; no error spam on partial permissions.

### Trade-offs
- One policy for "bad arg" vs "can't list a subdir": strict at the root is a user error;
  lenient inside is a best-effort scan.

---

## ADR-014 — Error handling and exit codes

- **Status:** Accepted

### Context
Malformed patterns, sizes, dates, and ranks of CLI mistakes must fail cleanly.

### Decision
- Domain validation uses exceptions: `std::invalid_argument` from the matcher
  (bad pattern), date/size parsers; everything is caught by `CliController` and printed
  to stderr with a `sniff:` prefix → exit **1**.
- `CommandParser` failures print the specific problem (e.g. "unknown option …",
  "option '--x' requires a value") → exit **1**.
- Exit codes: `0` success (even with zero matches), `1` any error, `130` (128+SIGINT)
  when a search is interrupted by Ctrl+C.

### Trade-offs
- Exceptions in the hot loop are only around construction (patterns), never per entry —
  per-entry matching uses branch/byte logic, so no throw overhead cost in the walk.

---

## ADR-015 — CLI parser shape

- **Status:** Accepted

### Context
The parser must stay simple, be testable, and cover the growing filter set.

### Decision
- One `CommandParser` class; positionals → first is the **pattern**, the rest are **paths**.
- Options accumulate into a single `FilterSpec` (or into the format field); `--` ends option
  parsing; long options support `--name=value`.
- Long options: `--type --extension --exclude --max-depth --min-depth --size
  --changed-within --changed-before --created-within --created-before --format`,
  plus switches `--hidden --follow --full-path --glob --fixed-strings
  --ignore-case --case-sensitive`.
- Short flags: `-H -L -p -g -F -i -s` (switches) and `-t -e -E -d -S` (value flags, inline
  values like `-ecpp` supported; `-S` accepts leading dashes for `-S-10k`).
- Values are validated at parse time (depth integers, size grammar, type/format tokens)
  with human-readable errors.

### Trade-offs
- Single-spec model (all filters in one `FilterSpec`) is fine now; if "OR of specs" is
  ever needed it would need a spec list + chain union (currently `SearchService` uses the
  first spec only).

---

## ADR-016 — Testing strategy

- **Status:** Accepted

### Context
sniff's correctness hinges on filesystem traversal, filtering, and formats — each hard to
test naively.

### Decision
- **Port injection**: `ISearchService`/`IEntryRepository` are faked in controller and
  service tests; no real I/O in unit tests.
- **Pure core**: scanner classification/conversion/path logic is a separate testable core
  fed synthetic `WIN32_FIND_DATA`.
- **Real-filesystem integration**: temp-dir fixtures (created, walked, removed) exercise
  the scanner and the full `CliController → SearchService → Win32Scanner` pipeline,
  including real symlinks (auto-skipped when creation is not permitted).
- GoogleTest via `FetchContent`; 180 tests, `gtest_discover_tests`; `/W4 /WX`.
- The tree-encoding regression underlined a trap: expected strings in tests can hide a
  charset bug because both sides get corrupted identically. The UTF-8 fix made those
  assertions meaningful again.

### Trade-offs
- Temp-dir tests are slower than pure unit tests and have minor OS flakiness (timestamps,
  access-denied permission), mitigated with tolerant assertions.

---

## ADR-017 — Dependency management & the `third-party/` folder

- **Status:** Accepted

### Context
GoogleTest is the only third-party dependency at present.

### Decision
- Dependencies are pulled by CMake `FetchContent` into the **build tree**
  (`build/_deps/`, gitignored) — no vendor bloat.
- `third-party/` exists as a placeholder for any future vendored code; it is kept in
  git via a `.gitkeep` so the folder isn't lost on clone.

### Trade-offs
- FetchContent requires network on first configure (cached afterwards).
- Vendoring would enable offline builds at the cost of repo size and upgrade pain.

---

## ADR-018 — CLI-level behavior shortcuts accepted for MVP

- **Status:** Accepted

### Context
Some `fd` conveniences were explicitly deferred to keep the first working version small.

### Decision
- A **pattern is always required** — there is no "list everything" invocation yet.
- Empty matches still exit `0` and print nothing (table) / an empty array (JSON).
- Progress reporting exists in the service (throttled ≥1024 entries or 50 ms) but has no
  CLI surface yet.

### Trade-offs
- Documented as known limitations in the README backlog rather than silently
  inconsistent behavior.

---

## Backlog (known future work, not yet decided)

- `--max-results`, `-1` (one match per dir), `-q` (quiet), `-a`, `-0` (NUL-separated).
- Real executable-bit (ACL/API) detection beyond the extension heuristic.
- Stats summary line in table output (`QueryResultStats` is computed but unused).
- `GetCommandLineW()` for true UTF-8 `argv` on Windows (current `main(argv)` uses the
  ANSI codepage — ASCII-safe today).
- Skipping hidden directories in the *walk* when hidden output is off (perf only).

---
*Last updated: 2026-08-12.*