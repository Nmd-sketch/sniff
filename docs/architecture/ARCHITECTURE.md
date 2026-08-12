# sniff — Architecture

This document describes the current architecture of the `sniff` repo with Mermaid
diagrams. It is a snapshot of `main`; see `../design/DECISIONS.md` for the rationale
behind these shapes (layers, ports, cancellation, encoding, …).

## The four layers

```

| layer            | lives in          | job                                          | may depend on |
|------------------|-------------------|----------------------------------------------|---------------|
| interface        | src/interface/    | CLI parsing + output formatting              | application   |
| application      | src/application/  | use-case orchestration, DTOs, primary port   | domain        |
| domain           | src/domain/       | entry model, filters, matching, sorting      | nothing       |
| infrastructure   | src/infrastructure/ | concrete Win32 filesystem scanner          | domain        |
```

Dependencies point *inward*: nothing above `domain` is known to `domain`. CMake enforces
this: `interface_layer PRIVATE application_layer`, `application_layer PUBLIC
domain_layer`, `infrastructure_layer PUBLIC domain_layer`.

## Component diagram

```mermaid
flowchart TB
    Main["main() · src/main.cpp"]

    subgraph IF["interface layer"]
        subgraph ICLI["cli/"]
            CC["CliController"]
            Parser["CommandParser"]
        end
        subgraph IFMT["formatter/"]
            FIf["Formatter (interface)"]
            Tbl["TableFormatter"]
            Tree["TreeFormatter"]
            Jsn["JsonFormatter"]
        end
    end

    subgraph APP["application layer"]
        subgraph ADTO["dto/"]
            Cfg["Config"]
            SCfg["ScanConfig"]
            QRes["QueryResult + QueryResultStats"]
        end
        AIS["ISearchService  (primary port)"]
        subgraph ASVC["service/"]
            Svc["SearchService"]
            Sig["SignalHandler  (Win / Posix)"]
        end
    end

    subgraph DOM["domain layer"]
        subgraph DMOD["model/"]
            IEnt["IEntry (interface)"]
            DEnt["DomainEntry"]
            FSpec["FilterSpec"]
            Token["CancellationToken"]
        end
        subgraph DPORT["ports/"]
            IFilt["IFilter"]
            IRepo["IEntryRepository  (secondary port)"]
        end
        subgraph DSVC["service/"]
            Matr["Matcher  (regex/glob/fixed)"]
            Fac["FilterFactory"]
            Chain["FilterChain"]
            Sortr["Sorter"]
        end
        subgraph DFIL["service/filters/"]
            FILS["Name · Hidden · Type · Extension · Size · Depth · Date · Exclude"]
        end
    end

    subgraph INF["infrastructure layer"]
        WCore["Win32ScanCore  (pure helpers)"]
        WScan["Win32Scanner"]
        Win["Win32 API: FindFirstFileW / FindNextFileW"]
    end

    Main --> CC

    CC --> Parser
    CC -. "builds" .-> SCfg
    CC --> AIS
    CC --> FIf
    FIf --> Tbl
    FIf --> Tree
    FIf --> Jsn

    AIS <--> Svc
    Svc --> Fac
    Fac --> Chain
    Chain <--> FILS
    Chain -. implements .-> IFilt
    Svc --> Sortr
    Svc -. "returns" .-> QRes

    Svc <--> IRepo
    WScan <--> IRepo
    WScan --> WCore
    WScan --> Win

    IEnt --> DEnt
```

### Read as data flow

`main` → `CliController` → (`CommandParser` for specs, `SignalHandler`+`CancellationToken`
for Ctrl+C) → `SearchService` → `FilterChain` **and** `Sorter` **and** `Win32Scanner` →
matched `IEntry`s → `TableFormatter`/`TreeFormatter`/`JsonFormatter` → stdout.

The two ports (`ISearchService` primary, `IEntryRepository` secondary) are the seams that
let tests substitute fakes for the real scanner/CLI.

## Key type relationships

```mermaid
classDiagram
    direction LR

    class ISearchService {
        <<interface>>
        +search(config, token) QueryResult
    }
    class SearchService {
        +search(config, token) QueryResult
    }
    class IEntryRepository {
        <<interface>>
        +scan(paths, spec, sink, token)
    }
    class Win32Scanner {
        +scan(paths, spec, sink, token)
    }
    class IEntry {
        <<interface>>
        +getName() string
        +getPath() string
        +getType() EntryType
        +isHidden() bool
        +isExecutable() bool
        +getSizeBytes() uintmax_t
        +getCreatedAt() time_point
        +getModifiedAt() time_point
    }
    class DomainEntry
    class QueryResult {
        +entries list~IEntry~
        +stats QueryResultStats
        +aborted bool
    }
    class Formatter {
        <<interface>>
        +formatEntries(entries) string
    }
    class CommandParser {
        +parse(args) bool
        +getCommands() vector~string~
        +getFilterSpecs() vector~FilterSpec~
    }

    SearchService ..|> ISearchService
    SearchService --> IEntryRepository
    Win32Scanner ..|> IEntryRepository
    DomainEntry ..|> IEntry
    QueryResult o-- IEntry
    SearchService --> QueryResult
    CommandParser --> Formatter : selects by --format
    Formatter <|-- TableFormatter
    Formatter <|-- TreeFormatter
    Formatter <|-- JsonFormatter
```

## Search flow (a full run of `sniff <pattern> <path>`)

```mermaid
sequenceDiagram
    participant CLI as CliController
    participant P as CommandParser
    participant SIG as SignalHandler
    participant TOK as CancellationToken
    participant SVC as SearchService
    participant FAC as FilterFactory
    participant CH as FilterChain
    participant SC as Win32Scanner
    participant SOR as Sorter
    participant FMT as Formatter

    CLI->>P: parse(args)
    P-->>CLI: commands (pattern + paths) + FilterSpec
    CLI->>SVC: search(ScanConfig, token)
    Note over CLI,SIG: registers signal handler → SIGINT → token.requestStop()
    SVC->>FAC: createChain(pattern, spec)
    FAC-->>SVC: FilterChain
    loop for each path
        Note over SC: depth-limited walk, UTF-8 names, symlink policy
        SVC->>SC: scan(path, spec, sink, token)
        loop each entry
            SC-->>SVC: unique_ptr<IEntry> + depth
            alt token.isStopped()
                SVC->>SVC: abort + mark QueryResult.aborted
            else chain.matches(entry, depth)
                SVC->>CH: matches(entry, depth)
                SVC->>SVC: collect + stats
            end
        end
    end
    SVC->>SOR: sort(entries)
    SVC-->>CLI: QueryResult{entries, stats, aborted}
    alt aborted
        CLI-->>CLI: print "interrupted", return 130
    else
        CLI->>FMT: formatEntries(entries)
        FMT-->>CLI: table | tree | json text
        CLI-->>CLI: print to stdout, return 0
    end
```

Errors that throw (missing root, malformed pattern/date/size) are caught by
`CliController`, printed to stderr, and exit with code `1`.

## Testing architecture

- GoogleTest suites in `tests/`, discovered via `gtest_discover_tests` (CTest).
- Unit tests drive `ISearchService` / `IEntryRepository` **fakes**; the scanner's pure
  core (`Win32ScanCore`) is fed synthetic `WIN32_FIND_DATA`.
- Integration tests build real temp-dir trees and run the whole
  `CliController → SearchService → Win32Scanner` pipeline, including real symlinks.
- See `src/infrastructure` for the scanner and `tests/CMakeLists.txt` for wiring.