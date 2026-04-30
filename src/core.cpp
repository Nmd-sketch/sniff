#include "../include/core.hpp"

[[nodiscard]] std::vector<sniff::Entry>
sniff::find(std::string_view root_path, const int max_depth,
            const std::uintmax_t min_size, const std::uintmax_t max_size,
            const bool ignore_hidden) {
  std::vector<Entry> results;
  
  std::string_view user_ext = "_all_ext";
  results = sniff::raw_scan(root_path, user_ext, max_depth, ignore_hidden, min_size, max_size);

  return results;
}

[[nodiscard]] std::vector<sniff::Entry>
sniff::glob_find(std::string_view root_path,
                 std::string_view extension, const int max_depth,
                 const std::uintmax_t min_size, const std::uintmax_t max_size,
                 const bool ignore_hidden) {
  // Always check if the path is valid
  std::vector<Entry> results;
  
  results = sniff::raw_scan(root_path, extension, max_depth, ignore_hidden, min_size, max_size);

  return results;
}
