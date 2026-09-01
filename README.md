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
- **180 unit + integration tests** (GoogleTest), clean `/W4 /WX` build.
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
ctest --test-dir build       # run the 180 tests
```

GoogleTest is downloaded by CMake `FetchContent` into `build/_deps/` (gitignored) and
cached after the first configure.

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