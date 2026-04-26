#include "../include/core.hpp"

// NEW: We check what type of char this OS uses
using charT = std::filesystem::path::value_type;

namespace {
bool is_hidden(const std::filesystem::path &p) {
  std::basic_string_view<charT> filename = p.filename().native();
  return !filename.empty() && filename[0] == '.';
}
} // namespace

[[nodiscard]] std::vector<sniff::Entry>
sniff::find(const std::filesystem::path &root_path, const int max_depth,
            const std::uintmax_t min_size, const std::uintmax_t max_size,
            const bool ignore_hidden) {
  // If the path doesn't exists we just return an empty vector
  std::vector<Entry> results;
  if (!std::filesystem::exists(root_path) ||
      !std::filesystem::is_directory(root_path)) [[unlikely]]
    return results;

  results.reserve(4096);

  // We create an iterator for the root path
  auto dir_iterator = std::filesystem::recursive_directory_iterator(root_path);

  // We then iterate through each directory recursively
  for (const auto &item : dir_iterator) {
    bool is_directory = item.is_directory();
    // If the iterator depth exceeds the max depth then we disable the
    // pending recursion and iterate to the next folder
    if (max_depth > -1 && is_directory && dir_iterator.depth() >= max_depth) {
      dir_iterator.disable_recursion_pending();
    }

    // If we are ignoring hidden files and this one is hidden
    // we skip it
    if (ignore_hidden && is_hidden(item.path())) [[unlikely]] {
      // If it's a hidden directory then we also skip it
      if (is_directory) {
        dir_iterator.disable_recursion_pending();
      }
      continue;
    }

    // If the item is a directory we skip it
    if (is_directory) [[unlikely]] {
      continue;
    }

    std::uintmax_t size = item.file_size();
    if (size < min_size || size > max_size) {
      continue;
    }

    Entry entry;
    entry.path = std::move(item.path());
    entry.is_directory = false;
    entry.size_bytes = size;

    // We push the results back into our vector
    results.push_back(entry);
  }

  return results;
}

[[nodiscard]] std::vector<sniff::Entry>
sniff::glob_find(const std::filesystem::path &root_path,
                 std::string_view extension, const int max_depth,
                 const std::uintmax_t min_size, const std::uintmax_t max_size,
                 const bool ignore_hidden) {
  // Always check if the path is valid
  std::vector<Entry> results;
  if (!std::filesystem::exists(root_path) ||
      !std::filesystem::is_directory(root_path)) [[unlikely]]
    return results;

  results.reserve(4096);

  // We create a reduced view of the user provided extension
  // and we transform it to lowercase to perform case insensitive comparison
  // NEW: We cast it to charT
  auto user_extension_view =
      extension | std::views::drop_while([](char c) { return c == '.'; }) |
      std::views::transform([](unsigned char c) -> charT {
        return static_cast<charT>(std::tolower(c));
      });

  // We create an iterator for the root path
  auto dir_iterator = std::filesystem::recursive_directory_iterator(root_path);

  // We iterate through each directory recursively
  for (const auto &item : dir_iterator) {
    bool is_directory = item.is_directory();
    // If the iterator depth exceeds the max depth then we disable the
    // pending recursion and iterate to the next folder
    if (max_depth > -1 && is_directory && dir_iterator.depth() >= max_depth) {
      dir_iterator.disable_recursion_pending();
    }

    // If we are ignoring hidden files and this one is hidden
    // we skip it
    if (ignore_hidden && is_hidden(item.path())) {
      // If it's a hidden directory then we also skip it
      if (is_directory) {
        dir_iterator.disable_recursion_pending();
      }
      continue;
    }

    // If the current item is a directory we skip it entirely
    if (is_directory) [[unlikely]] {
      continue;
    }

    std::basic_string_view<charT> native_extension =
        item.path().extension().native();
    auto ext_view = native_extension |
                    std::views::drop_while([](charT c) { return c == '.'; }) |
                    std::views::transform([](charT c) -> charT {
                      if constexpr (sizeof(charT) == sizeof(wchar_t)) {
                        return std::towlower(c);
                      } else {
                        return std::tolower(static_cast<unsigned char>(c));
                      }
                    });

    if (std::ranges::equal(user_extension_view, ext_view)) [[likely]] {
      // Construction of the entry
      std::uintmax_t size = item.file_size();

      if (size < min_size || size > max_size) [[unlikely]] {
        continue;
      }

      Entry entry;
      entry.path = std::move(item.path());
      entry.is_directory = false;
      entry.size_bytes = size;

      results.push_back(entry);
    }
  }

  return results;
}
