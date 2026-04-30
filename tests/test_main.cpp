#include "../include/core.hpp"
#include <catch2/catch_test_macros.hpp>
#include <limits>
#include <string>
#include <iostream>

// Since ctest runs from inside the build/ folder,
// searching "." searches the build folder itself!
const std::string build_dir = ".";

// ==========================================================
// String-path helpers (Entry::path is now std::string)
// ==========================================================

static std::string_view path_extension(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return {};
    auto slash = path.find_last_of("/\\");
    if (slash != std::string::npos && slash > dot) return {};
    return std::string_view(path).substr(dot);
}

static std::string_view path_filename(const std::string& path) {
    auto slash = path.find_last_of("/\\");
    if (slash == std::string::npos) return path;
    return std::string_view(path).substr(slash + 1);
}

// ==========================================================
// FIND (-a) TESTS
// ==========================================================

TEST_CASE("find returns results in a valid directory", "[find]") {
    auto results = sniff::find(build_dir);
    REQUIRE_FALSE(results.empty());
}

TEST_CASE("find returns empty for non-existent path", "[find][edge]") {
    auto results = sniff::find("path/to/absolute/garbage");
    REQUIRE(results.empty());
}

TEST_CASE("find returns empty when passed a file instead of directory",
          "[find][edge]") {
    auto results = sniff::find("CMakeCache.txt");
    REQUIRE(results.empty());
}

TEST_CASE("find respects max depth 0 (immediate children only)", "[find][depth]") {
    auto all_results = sniff::find(build_dir);
    auto shallow_results = sniff::find(build_dir, 0);

    REQUIRE(shallow_results.size() <= all_results.size());
    REQUIRE_FALSE(shallow_results.empty());

    for (const auto &entry : shallow_results) {
        if (entry.is_directory) continue;  // Allow the CMakeFiles dir itself
        REQUIRE(entry.path.find("CMakeFiles") == std::string::npos);
    }
}

TEST_CASE("find respects max depth 1", "[find][depth]") {
    auto depth_0 = sniff::find(build_dir, 0);
    auto depth_1 = sniff::find(build_dir, 1);

    REQUIRE(depth_1.size() > depth_0.size());
}

TEST_CASE("find respects min size filter", "[find][size]") {
    auto all_results = sniff::find(build_dir);
    auto large_results = sniff::find(build_dir, -1, 1000);

    REQUIRE(large_results.size() < all_results.size());

    for (const auto& entry : large_results) {
        REQUIRE(entry.size_bytes >= 1000);
    }
}

TEST_CASE("find respects max size filter", "[find][size]") {
    auto tiny_results = sniff::find(build_dir, -1, 0, 10);

    for (const auto& entry : tiny_results) {
        REQUIRE(entry.size_bytes <= 10);
    }
}

// ==========================================================
// GLOB_FIND (-e) TESTS
// ==========================================================

TEST_CASE("glob_find filters by extension", "[glob]") {
    auto all = sniff::find(build_dir);
    auto txt_files = sniff::glob_find(build_dir, "txt");

    REQUIRE(txt_files.size() < all.size());
    REQUIRE_FALSE(txt_files.empty());

    for (const auto& entry : txt_files) {
        REQUIRE(path_extension(entry.path) == ".txt");
    }
}

TEST_CASE("glob_find is case insensitive", "[glob][case]") {
    auto lower = sniff::glob_find(build_dir, "txt");
    auto upper = sniff::glob_find(build_dir, "TXT");
    auto mixed = sniff::glob_find(build_dir, "TxT");

    REQUIRE(lower.size() == upper.size());
    REQUIRE(upper.size() == mixed.size());
}

TEST_CASE("glob_find handles dot prefix gracefully", "[glob][dot]") {
    auto no_dot = sniff::glob_find(build_dir, "txt");
    auto with_dot = sniff::glob_find(build_dir, ".txt");

    REQUIRE(no_dot.size() == with_dot.size());
}

TEST_CASE("glob_find returns empty for non-existent extension",
          "[glob][edge]") {
    auto results = sniff::glob_find(build_dir, "zzz_fake_extension_zzz");
    REQUIRE(results.empty());
}

TEST_CASE("glob_find combines extension, depth, and size", "[glob][combined]") {
    auto results = sniff::glob_find(build_dir, "txt", 0, 1);

    for (const auto& entry : results) {
        REQUIRE(path_extension(entry.path) == ".txt");
        REQUIRE(entry.size_bytes >= 1);
        REQUIRE(entry.path.find("CMakeFiles") == std::string::npos);
    }
}

TEST_CASE("find skips hidden files by default", "[find][hidden]") {
    auto all_results = sniff::find(build_dir);
    auto unrestricted = sniff::find(build_dir, -1, 0,
                                   std::numeric_limits<std::uintmax_t>::max(),
                                   false);

    REQUIRE(unrestricted.size() >= all_results.size());

    for (const auto& entry : all_results) {
        auto name = path_filename(entry.path);
        REQUIRE_FALSE(name.empty());
        REQUIRE(name[0] != '.');
    }
}
