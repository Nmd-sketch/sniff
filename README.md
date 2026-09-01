# sniff

A fast, `fd`-like file search tool for Windows, written in C++20.

`sniff <pattern> [paths…] [options]` walks a directory tree using the native Win32
directory API, filters the entries against a composed filter chain, and prints the
results. It is an MVP: everything from argument parsing down to the filesystem scan is
real, tested, and wired together.

---

## Status

- **Working MVP** — `sniff.exe` searches real directories with filters, formats, and
  Ctrl+C cancellation.
- **190 unit + integration tests** (GoogleTest), clean `/W4 /WX` build.
- See `docs/design/DECISIONS.md` for the architectural decisions behind the project, and
  [Known limitations](#known-limitations) below.

## Requirements

- Windows (traversal uses the Win32 API).
- CMake ≥ 3.20.
- A C++20 compiler (MSVC, `/W4 /WX`).

## Build & test

```powershell
cmake -S . -B build          # configure (MSVC: /W4 /WX, UTF-8)
cmake --build build          # build
build\Debug\sniff.exe        # the binary
ctest --test-dir build       # run the 190 tests
```

GoogleTest is downloaded by CMake `FetchContent` into `build/_deps/` (gitignored) and
cached after the first configure.

## Performance

`sniff` is benchmarked against `fd 10.4.2` with `hyperfine 1.20.0` on this
machine: *11th Gen Intel Core i3-1125G4, 4 cores / 8 threads, Windows 10,
NTFS*. Both binaries are scanned over one identical corpus — the project's
source tree replicated into 64 modules, 5,315 files / 1,600 directories
(between 6 KB and 40 KB per file) — with each command returning exactly the
same result set. 10 runs after 3 warm-ups, stdout discarded so console
rendering is not measured.

| Scenario | sniff (0.1.0) | fd (10.4.2) | Ratio |
|---|---|---|---|
| List every name (`sniff '*' -g` / `fd .`) | 112.0 ± 3.4 ms | 86.4 ± 3.5 ms | fd 1.30× |
| All `.cpp` files (`--extension cpp` / `-e cpp`) | 105.0 ± 2.8 ms | 89.4 ± 5.8 ms | fd 1.17× |
| Literal `cmake`, case-insensitive (`-F -i`) | 97.9 ± 6.9 ms | 91.8 ± 5.7 ms | fd 1.07× |

Raw hyperfine output (mean ± σ, min, max, relative):

```text
| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| sniff '*' <corpus> -g                         | 112.0 ± 3.4 | 108.9 | 118.5 | 1.30 ± 0.07 |
| fd --no-ignore -I . <corpus>              |  86.4 ± 3.5 |  82.0 |  92.1 | 1.00 |
| sniff '*' <corpus> -g --extension cpp     | 105.0 ± 2.8 | 102.2 | 111.9 | 1.21 ± 0.06 |
| fd --no-ignore -e cpp . <corpus>          |  89.4 ± 5.8 |  82.6 | 100.4 | 1.03 ± 0.08 |
| sniff cmake <corpus> -F -i                |  97.9 ± 6.9 |  88.4 | 108.8 | 1.13 ± 0.09 |
| fd --no-ignore -F -i cmake <corpus>       |  91.8 ± 5.7 |  84.4 | 100.0 | 1.06 ± 0.08 |
```

Methodology notes:

- Sniff is a **Release** build (`/O2`); both tools scan the exact same files.
- fd always excludes git plumbing files (`.gitkeep`, `.gitignore`) even with
  `--no-ignore --hidden`, so those placeholders are left out of the corpus and
  fd is given `--no-ignore -I` to neutralize its ignore/hidden defaults. Every
  pair returns the same number of results.
- Commands run through `cmd /c "… > NUL"` so the search work, not terminal
  output, is timed.

## Usage

```
sniff <pattern> [paths…] [options]
```

- The **first positional** is the search pattern; the remaining positionals are scan
  roots (default `.` when omitted).
- Patterns are **regular expressions by default**, matched unanchored against the file
  name (`std::regex`). Use `--glob` for shell-style globs or `--fixed-strings` for a
  literal substring.
- In **glob mode** `.` is a literal dot and `*` matches any characters; to match
  everything use `'*'`. A pattern like `'*.cpp'` already finds `.cpp` files anywhere
  in the tree, so no leading `.*` is needed.
- Files **and** directories are matched and reported.

> **PowerShell note:** quote patterns so the shell doesn't expand them first:
> `sniff '*.cpp' . --glob` (use single quotes).

### Examples

```powershell
sniff '\.cpp$' .                  # regex: every .cpp under the current dir
sniff '*.cpp' . -g                # glob version
sniff 'Config\.h$' src --glob     # search only inside src/
sniff cpp . -F                    # literal substring "cpp" anywhere in a name
sniff '*' . -g --extension cpp   # only .cpp files, anywhere in the tree
sniff '*' . -g --type d          # only directories
sniff '*' . -g --max-depth 2     # two levels deep
sniff '*' . -g --size +10k       # files larger than 10 KB
sniff '*' . -g -S -1m            # files smaller than 1 MB
sniff '*' . -g --changed-within 2d    # modified in the last 2 days
sniff '*' . -g --changed-before '2026-01-01 00:00:00'  # modified before a date
sniff '*' . -g --hidden -i       # include dot-files, case-insensitive
sniff '*' . -g --format tree     # render as a tree
sniff '*' . -g --format json     # machine-readable JSON
```

### Options

#### Matching

| Option | Short | Meaning |
|--------|-------|---------|
| `--glob` | `-g` | shell glob pattern (`*`, `?`, `[...]`), matched against the full name |
| `--fixed-strings` | `-F` | literal substring search |
| `--ignore-case` | `-i` | case-insensitive matching (glob/regex/fixed) |
| `--case-sensitive` | `-s` | force case-sensitive matching (default) |
| `--full-path` | `-p` | match against the full path instead of the file name |

#### Filters

| Option | Short | Meaning |
|--------|-------|---------|
| `--type TYPE` | `-t` | keep entries of a type; repeatable. Tokens: `f/file`, `d/dir/directory`, `l/symlink`, `x/executable`, `e/empty` |
| `--extension EXT` | `-e` | keep files with this extension; repeatable (leading dot optional) |
| `--exclude MATCH` | `-E` | drop entries whose case-insensitive path *contains* this text; repeatable |
| `--size SIZESPEC` | `-S` | size filter, see [Sizes](#sizes) |
| `--max-depth N` | `-d` | don't descend deeper than N levels |
| `--min-depth N` | | don't report entries shallower than N levels |
| `--changed-within D` | | modified within the last duration, e.g. `90s` `5m` `2h` `1d` `3w` |
| `--changed-before T` | | modified before an absolute timestamp, `YYYY-MM-DD [HH:MM:SS]` |
| `--created-within D` | | created within the last duration |
| `--created-before T` | | created before an absolute timestamp, `YYYY-MM-DD [HH:MM:SS]` |

#### Behavior

| Option | Short | Meaning |
|--------|-------|---------|
| `--hidden` | `-H` | include hidden entries (excluded by default) |
| `--follow` | `-L` | follow symlinked directories during traversal (cycle-safe) |
| `--format FMT` | | output format: `table` (default), `tree`, `json` |

Long options accept `--name=value`. `--` ends option parsing, so a path beginning with
`-` can be passed literally. Several options are repeatable (`--type`, `--extension`,
`--exclude`).

### Sizes

`--size` accepts `[+-]NUM[UNIT]`:

- No sign means an exact size; `+` means "at least", `-` means "at most".
- Units (case-insensitive): `b`, `k`, `m`, `g`, `t` (powers of 10) and `ki`, `mi`,
  `gi`, `ti` (powers of 2).
- Examples: `--size +10k`, `--size -1g`, `--size 5ki`, `-S+2m`, `-S-10k`.

### Output

- **table** (default): columns `TYPE NAME SIZE MODIFIED` (`f`/`d`/`l` for file /
  directory / symlink; sizes like `2.5 MiB`; timestamps in UTC `YYYY-MM-DD HH:MM:SS`).
- **tree**: ASCII-free UTF-8 box-drawing tree derived from entry paths.
- **json**: `{"entries":[{"name","path","type","size","created","modified","hidden"}]}`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | success (including zero matches) |
| `1`  | any error (bad option, missing pattern, missing root, invalid pattern/date/size) |
| `130`| interrupted by Ctrl+C during a search |

## Project layout

```
src/
  interface/      CLI parsing + output formatting (CliController, CommandParser, formatters)
  application/    use-case orchestration (SearchService), DTOs, ISearchService port
  domain/         pure logic: entry model, MatchMode/CaseMode, 8 filters, Matcher,
                  Sorter, FilterChain/FilterFactory, CancellationToken, IEntryRepository port
  infrastructure/ Win32 filesystem scanner (Win32Scanner + Win32ScanCore)
tests/            GoogleTest suites (incl. temp-dir integration + end-to-end CLI tests)
docs/design/      architecture decision log (DECISIONS.md)
third-party/      placeholder for future vendored dependencies (empty)
```

## Known limitations

- A **pattern is always required**; "list everything" is not an invocation yet.
- `argv` on Windows arrives in the ANSI codepage; non-ASCII **arguments** may be mangled
  (ASCII is safe). A `GetCommandLineW()` upgrade is planned.
- Rendering assumes a UTF-8-capable console/terminal (Windows Terminal, modern conhost);
  legacy `conhost` may mis-draw the tree glyphs.
- Hidden directories are still *walked* at the filesystem level even when excluded from
  output (a future traversal optimization).
- `--type executable` uses an extension/PATHEXT heuristic (there is no unix exec bit on
  Windows).
- No progress/status output on the CLI yet (`QueryResultStats` is computed internally).

More background and the rulebook behind these decisions live in
[`docs/design/DECISIONS.md`](docs/design/DECISIONS.md).