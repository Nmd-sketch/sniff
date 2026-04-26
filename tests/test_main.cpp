#include "../include/core.hpp"
#include <catch2/catch_test_macros.hpp>

// Since ctest runs from inside the build/ folder,
// searching "." searches the build folder itself!
const std::filesystem::path build_dir = ".";

// ==========================================================
// FIND (-a) TESTS
// ==========================================================

TEST_CASE("find returns results in a valid directory", "[find]") {
  auto results = sniff::find(build_dir);
  // The build folder should ALWAYS have at least CMakeCache.txt
  REQUIRE_FALSE(results.empty());
}

TEST_CASE("find returns empty for non-existent path", "[find][edge]") {
  auto results = sniff::find("path/to/absolute/garbage");
  REQUIRE(results.empty());
}

TEST_CASE("find returns empty when passed a file instead of directory",
          "[find][edge]") {
  // CMakeCache.txt is guaranteed to exist in the build folder
  auto results = sniff::find("CMakeCache.txt");
  REQUIRE(results.empty());
}

TEST_CASE("find respects max depth 0 (immediate children only)",
          "[find][depth]") {
  auto all_results = sniff::find(build_dir);
  auto shallow_results = sniff::find(build_dir, 0);

  // Shallow must find less than or equal to deep
  REQUIRE(shallow_results.size() <= all_results.size());

  // Shallow should still find something (like CMakeCache.txt)
  REQUIRE_FALSE(shallow_results.empty());

  // Prove it actually skipped deep folders:
  // none of the shallow results should have "CMakeFiles" in their path
  for (const auto &entry : shallow_results) {
    REQUIRE(entry.path.string().find("CMakeFiles") == std::string::npos);
  }
}

TEST_CASE("find respects max depth 1", "[find][depth]") {
  auto depth_0 = sniff::find(build_dir, 0);
  auto depth_1 = sniff::find(build_dir, 1);

  // Depth 1 should find strictly more than depth 0
  REQUIRE(depth_1.size() > depth_0.size());
}

TEST_CASE("find respects min size filter", "[find][size]") {
  // 1000 bytes is a safe bet to filter out tiny .txt files
  // but keep larger object files (.o / .obj)
  auto all_results = sniff::find(build_dir);
  auto large_results = sniff::find(build_dir, -1, 1000);

  REQUIRE(large_results.size() < all_results.size());

  // Double check that every returned file is actually > 1000 bytes
  for (const auto &entry : large_results) {
    REQUIRE(entry.size_bytes >= 1000);
  }
}

TEST_CASE("find respects max size filter", "[find][size]") {
  // 10 bytes will filter out almost everything in a build folder
  auto tiny_results = sniff::find(build_dir, -1, 0, 10);

  for (const auto &entry : tiny_results) {
    REQUIRE(entry.size_bytes <= 10);
  }
}

// ==========================================================
// GLOB_FIND (-e) TESTS
// ==========================================================

TEST_CASE("glob_find filters by extension", "[glob]") {
  // ".txt" is 100% guaranteed to exist in a build folder (CMakeCache.txt)
  auto all = sniff::find(build_dir);
  auto txt_files = sniff::glob_find(build_dir, "txt");

  REQUIRE(txt_files.size() < all.size());
  REQUIRE_FALSE(txt_files.empty());

  // Absolute proof: manually check the extensions
  for (const auto &entry : txt_files) {
    REQUIRE(entry.path.extension() == ".txt");
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
  // Find .txt files, only at depth 0, that are larger than 0 bytes
  auto results = sniff::glob_find(build_dir, "txt", 0, 1);

  for (const auto &entry : results) {
    REQUIRE(entry.path.extension() == ".txt");
    REQUIRE(entry.size_bytes >= 1);
    // Ensure it didn't dig into subdirectories
    REQUIRE(entry.path.string().find("CMakeFiles") == std::string::npos);
  }
}

TEST_CASE("find skips hidden files by default", "[find][hidden]") {
    auto all_results = sniff::find(build_dir); // ignore_hidden defaults to true
    auto unrestricted = sniff::find(build_dir, -1, 0, std::numeric_limits<std::uintmax_t>::max(), false);
    
    // Unrestricted MUST find more files (like hidden CMake cache folders)
    REQUIRE(unrestricted.size() > all_results.size());
    
    // Prove none of the default results have a hidden folder in the path
    for (const auto& entry : all_results) {
        // A hidden folder would look like "CMakeFiles/.hidden_cache"
        // We make sure the immediate parent isn't hidden just to be safe,
        // but usually it's the top-level folder that's hidden.
        REQUIRE(entry.path.filename().string()[0] != '.');
    }
}
