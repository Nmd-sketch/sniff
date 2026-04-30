<div align="center">

  <h1>sniff</h1>

  **A blazing fast, safe, and scriptable file finder.**

  ![C++20](https://img.shields.io/badge/C++-20-blue.svg)
  ![Python](https://img.shields.io/badge/Python-3.x-yellow.svg)
  ![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

  [Features](#features) • [Benchmarks](#benchmarks) • [Installation](#installation) • [Quick Start](#quick-start) • [Python API](#python-api)
</div>

---

## Why sniff?

Standard `find` is powerful but clunky. It requires ancient syntax and spews permission errors when it hits hidden folders.

`sniff` is built in modern C++20. It outputs clean JSON for scripts, connects natively to Python via Pybind11, and skips hidden folders by default so you don't have to see `.git` garbage.

---

## Benchmarks

Tested scanning **70,000+ files** in a deep dependency tree on Windows 11 (MinGW GCC 15, Release `-O3`).

# v0.1.0
| Tool | Command | Mean Time | Pure CPU Time (`User`) | OS Overhead (`System`) |
| :--- | :--- | :--- | :--- | :--- |
| **`sniff` (C++20)** | `sniff -e cpp _deps` | 193.1 ms | **17.6 ms** | 173.5 ms |
| `fd` (Rust) | `fd "\.cpp$" _deps` | **60.8 ms** | 49.4 ms | 84.7 ms |
| POSIX `find` | `find _deps -name "*.cpp"` | ~260.0 ms | - | - |

*Note: `sniff`'s raw computation engine is nearly **3x faster** than `fd` at pure CPU math. The current total time is dominated by `std::filesystem` OS wrapper overhead, which will be optimized in v0.2 using bulk directory reading APIs.*

# v0.2.0 (Windows)
| Tool | Command | Mean Time | Pure CPU Time (`User`) | OS Overhead (`System`) |
| :--- | :--- | :--- | :--- | :--- |
| **`sniff` (C++20)** | `sniff -e cpp _deps` | 193.1 ms | **6.4 ms** | 34.1 ms |
| `fd` (Rust) | `fd "\.cpp$" _deps` | **60.8 ms** | 52.3 ms | 73.1 ms |
| POSIX `find` | `find _deps -name "*.cpp"` | ~260.0 ms | - | - |

*Note: The POSIX implementation is still a work in progress.*
---

## Installation (CLI)

**Windows (MSYS2/MinGW):**

```bash
git clone https://github.com/Nmd-sketch/sniff.git
cd sniff
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Quick Start

```bash
# Find all C++ files
sniff -e cpp .

# Find large files over 10MB
sniff -a . --min-size 10mb

# Limit search depth to 2 folders deep
sniff -e hpp . -d 2

# Output as JSON for scripts
sniff -e cpp . -j
```

## CLI Options

| Flag               | Description                                       |
| :----------------- | :------------------------------------------------ |
| `-e <ext>`         | Filter by extension (e.g., `-e cpp` or `-e .cpp`) |
| `-a`               | Show all files (ignores extension filter)         |
| `-d <num>`         | Max depth to traverse (default: infinite)         |
| `--min-size <val>` | Minimum file size (e.g., `500kb`, `2mb`)          |
| `--max-size <val>` | Maximum file size                                 |
| `-j`, `--json`     | Output results as a JSON array                    |
| `-u`               | Show hidden files (like `.git`, `.env`)           |

## Python API
`sniff` includes native Python bindings via Pybind11, compiled as a standalone `.pyd` file with zero
external dependencies.

```python
import sniff

# Find all python files, skipping hidden ones by default
files = sniff.glob_find("/path/to/project", "py")

for entry in files:
    print(f"File: {entry.path} | Size: {entry.size_bytes} bytes")
```
Parameters: `root_path` , `extension` , `max_depth` , `min_size` , `max_size` , `ignore_hidden`

## License
This project is licensed under the Apache License, Version 2.0. See the LICENSE file for details.

