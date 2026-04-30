#include "../include/core.hpp"
#include <catch2/catch_test_macros.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <ranges>

namespace fs = std::filesystem;

// ------------------------------------------------------------------
// Test fixture helpers
// ------------------------------------------------------------------

static fs::path g_test_root;

static void write_file(const fs::path &p, const std::string &content) {
    std::ofstream f(p);
    f << content;
}

static fs::path setup_fixture() {
    char tmpl[] = "/tmp/sniff_test_XXXXXX";
    char *dir = mkdtemp(tmpl);
    REQUIRE(dir != nullptr);
    fs::path root(dir);

    // Root-level entries
    write_file(root / "file.txt", "hello");           // size 5
    write_file(root / "FILE.TXT", "");                // size 0, case test
    write_file(root / "readme.md", "markdown");       // size 8
    write_file(root / ".hidden_file", "hid");         // size 3, hidden
    write_file(root / "large.bin", std::string(2000, 'x')); // size 2000
    write_file(root / "tiny.bin", "x");               // size 1

    // Subdirectory (depth 1)
    fs::create_directories(root / "subdir");
    write_file(root / "subdir" / "nested.txt", "nest"); // size 4
    write_file(root / "subdir" / ".hidden_nested", "h"); // size 1, hidden

    // Deeper directory (depth 2)
    fs::create_directories(root / "subdir" / "deeper");
    write_file(root / "subdir" / "deeper" / "deep.txt", "deeply"); // size 6

    return root;
}

static std::string path_extension(const std::string &path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return {};

    auto slash = path.find_last_of('/');
    if (slash != std::string::npos && slash > dot) return {};

    std::string ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    return ext;
}

static std::string_view path_filename(const std::string &path) {
    auto slash = path.find_last_of('/');
    if (slash == std::string::npos) return path;
    return std::string_view(path).substr(slash + 1);
}

// ------------------------------------------------------------------
// FIND (-a) TESTS
// ------------------------------------------------------------------

TEST_CASE("find returns results in a valid directory", "[find]") {
    auto root = setup_fixture();
    auto results = sniff::find(root.string());
    REQUIRE_FALSE(results.empty());

    // Should find: file.txt, FILE.TXT, readme.md, large.bin, tiny.bin,
    // subdir (dir), subdir/nested.txt, subdir/.hidden_nested (if not ignored),
    // subdir/deeper, subdir/deeper/deep.txt
    // But default find ignores hidden files, so .hidden_file and .hidden_nested skipped
    REQUIRE(results.size() >= 5);
}

TEST_CASE("find returns empty for non-existent path", "[find][edge]") {
    auto results = sniff::find("/tmp/sniff_nonexistent_garbage_path");
    REQUIRE(results.empty());
}

TEST_CASE("find returns empty when passed a file instead of directory", "[find][edge]") {
    auto root = setup_fixture();
    auto file_path = (root / "file.txt").string();
    auto results = sniff::find(file_path);
    REQUIRE(results.empty());
}

TEST_CASE("find respects max depth 0 (immediate children only)", "[find][depth]") {
    auto root = setup_fixture();
    auto results = sniff::find(root.string(), 0);

    REQUIRE_FALSE(results.empty());

    for (const auto &entry : results) {
        // Nothing from subdir/ should appear at depth 0
        REQUIRE(entry.path.find("/subdir/") == std::string::npos);
    }
}

TEST_CASE("find respects max depth 1", "[find][depth]") {
    auto root = setup_fixture();
    auto depth_0 = sniff::find(root.string(), 0);
    auto depth_1 = sniff::find(root.string(), 1);

    REQUIRE(depth_1.size() > depth_0.size());

    // depth 1 should include subdir/nested.txt but NOT subdir/deeper/deep.txt
    bool found_nested = false;
    bool found_deep = false;
    for (const auto &entry : depth_1) {
        if (entry.path.find("/subdir/nested.txt") != std::string::npos)
            found_nested = true;
        if (entry.path.find("/subdir/deeper/deep.txt") != std::string::npos)
            found_deep = true;
    }
    REQUIRE(found_nested);
    REQUIRE_FALSE(found_deep);
}

TEST_CASE("find respects min size filter", "[find][size]") {
    auto root = setup_fixture();
    auto results = sniff::find(root.string(), -1, 5);

    for (const auto &entry : results) {
        REQUIRE(entry.size_bytes >= 5);
    }

    // file.txt is exactly 5, readme.md is 8, large.bin is 2000
    // tiny.bin (1) should be excluded
    bool found_tiny = false;
    for (const auto &entry : results) {
        if (path_filename(entry.path) == "tiny.bin")
            found_tiny = true;
    }
    REQUIRE_FALSE(found_tiny);
}

TEST_CASE("find respects max size filter", "[find][size]") {
    auto root = setup_fixture();
    auto results = sniff::find(root.string(), -1, 0, 4);

    for (const auto &entry : results) {
        REQUIRE(entry.size_bytes <= 4);
    }
}

// ------------------------------------------------------------------
// GLOB_FIND (-e) TESTS
// ------------------------------------------------------------------

TEST_CASE("glob_find filters by extension", "[glob]") {
    auto root = setup_fixture();
    auto txt_files = sniff::glob_find(root.string(), "txt");

    REQUIRE_FALSE(txt_files.empty());

    for (const auto &entry : txt_files) {
        REQUIRE(path_extension(entry.path) == ".txt");
    }

    // Should find file.txt and subdir/nested.txt and subdir/deeper/deep.txt
    // (unless depth-limited by default, but glob_find likely uses -1)
    REQUIRE(txt_files.size() >= 2);
}

TEST_CASE("glob_find is case insensitive", "[glob][case]") {
    auto root = setup_fixture();
    auto lower = sniff::glob_find(root.string(), "txt");
    auto upper = sniff::glob_find(root.string(), "TXT");
    auto mixed = sniff::glob_find(root.string(), "TxT");

    REQUIRE(lower.size() == upper.size());
    REQUIRE(upper.size() == mixed.size());

    // Should match both file.txt and FILE.TXT
    REQUIRE(lower.size() >= 2);
}

TEST_CASE("glob_find handles dot prefix gracefully", "[glob][dot]") {
    auto root = setup_fixture();
    auto no_dot = sniff::glob_find(root.string(), "txt");
    auto with_dot = sniff::glob_find(root.string(), ".txt");

    REQUIRE(no_dot.size() == with_dot.size());
}

TEST_CASE("glob_find returns empty for non-existent extension", "[glob][edge]") {
    auto root = setup_fixture();
    auto results = sniff::glob_find(root.string(), "zzz_fake_extension_zzz");
    REQUIRE(results.empty());
}

TEST_CASE("glob_find combines extension, depth, and size", "[glob][combined]") {
    auto root = setup_fixture();
    auto results = sniff::glob_find(root.string(), "txt", 1, 1);

    for (const auto &entry : results) {
        REQUIRE(path_extension(entry.path) == ".txt");
        REQUIRE(entry.size_bytes >= 1);
        // Depth 1 means no deeper/ entries
        REQUIRE(entry.path.find("/deeper/") == std::string::npos);
    }

    // Should find file.txt and subdir/nested.txt
    REQUIRE(results.size() == 2);
}

TEST_CASE("find skips hidden files by default", "[find][hidden]") {
    auto root = setup_fixture();
    auto restricted = sniff::find(root.string());
    auto unrestricted = sniff::find(root.string(), -1, 0,
                                    std::numeric_limits<std::uintmax_t>::max(),
                                    false);

    REQUIRE(unrestricted.size() >= restricted.size());

    // Restricted (default) should NOT contain hidden files
    for (const auto &entry : restricted) {
        auto name = path_filename(entry.path);
        REQUIRE_FALSE(name.empty());
        REQUIRE(name[0] != '.');
    }

    // Unrestricted SHOULD contain the hidden files we created
    bool found_hidden_root = false;
    bool found_hidden_sub = false;
    for (const auto &entry : unrestricted) {
        if (path_filename(entry.path) == ".hidden_file")
            found_hidden_root = true;
        if (path_filename(entry.path) == ".hidden_nested")
            found_hidden_sub = true;
    }
    REQUIRE(found_hidden_root);
    REQUIRE(found_hidden_sub);
}
