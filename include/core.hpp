#pragma once
#include <cstdint>
#include <filesystem>
#include <string_view>
#include <vector>
#include <limits>
#include <ranges>
#include <algorithm>

namespace sniff {

// Struct that we will use to keep track of the data
struct Entry {
  std::filesystem::path path;
  std::uintmax_t size_bytes = 0;
  bool is_directory = false;
};

// Returns a vector of all the items found in the root path
std::vector<Entry> find(
    const std::filesystem::path &root_path,
    int max_depth = -1,
    std::uintmax_t min_size = 0,
    std::uintmax_t max_size = std::numeric_limits<std::uintmax_t>::max(),
    bool ignore_hidden = true);

// Returns a vector of all the items found in the root path
// that match a given wildcard. Ex: *.exe, *.jpg
std::vector<Entry> glob_find(
    const std::filesystem::path &root_path,
    std::string_view extension,
    int max_depth = -1,
    std::uintmax_t min_size = 0,
    std::uintmax_t max_size = std::numeric_limits<std::uintmax_t>::max(),
    bool ignore_hidden = true);
} // namespace sniff
