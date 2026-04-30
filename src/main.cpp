#include "../include/core.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <limits>
#include <nlohmann/json.hpp>
#include <ranges>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <windows.h>
#endif

using json = nlohmann::json;

void print_help() {
  std::cout << "Usage: sniff [OPTIONS] [PATH]\n"
            << "\n"
            << "Options:\n"
            << "  -a              Scan all files and directories\n"
            << "  -e <ext>        Find files by extension (e.g., -e cpp)\n"
            << "  -h              Show this help message\n"
            << "  -d <n>          Maximum directory depth (default: unlimited)\n"
            << "  --min-size      Minimum file size (e.g., 100mb, 400kb)\n"
            << "  --max-size      Maximum file size (e.g., 100mb, 400kb)\n"
            << "  -j, --json      Output as JSON\n"
            << "  -u, --unrestricted  Include hidden files and directories\n"
            << "\n"
            << "If no path is provided, defaults to '.' (current directory)\n";
}

std::uintmax_t parse_size(std::string_view input) {
  auto is_digit = [](unsigned char c) { return std::isdigit(c); };

  auto num_view = input | std::views::take_while(is_digit);
  auto suffix_view =
      input | std::views::drop_while(is_digit) |
      std::views::transform([](unsigned char c) { return std::tolower(c); });

  std::uintmax_t number = 0;
  if (!num_view.empty()) {
    std::string s;
    std::ranges::copy(num_view, std::back_inserter(s));
    number = std::stoull(s);
  }

  if (std::ranges::equal(suffix_view, std::string_view("kb")) ||
      std::ranges::equal(suffix_view, std::string_view("k"))) {
    return number * 1024ULL;
  }
  if (std::ranges::equal(suffix_view, std::string_view("gb")) ||
      std::ranges::equal(suffix_view, std::string_view("g"))) {
    return number * 1024ULL * 1024ULL * 1024ULL;
  }
  if (std::ranges::equal(suffix_view, std::string_view("mb")) ||
      std::ranges::equal(suffix_view, std::string_view("m"))) {
    return number * 1024ULL * 1024ULL;
  }
  return number;
}

int main(int argc, char *argv[]) {

  std::string_view target_path = ".";
  std::string_view target_ext = "";
  bool all_files = false;
  int max_depth = -1;
  std::uintmax_t min_size = 0;
  std::uintmax_t max_size = std::numeric_limits<std::uintmax_t>::max();
  bool output_json = false;
  bool ignore_hidden = true;

  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];

    if (arg == "-h" || arg == "--help") {
      print_help();
      return 0;
    } else if (arg == "-e") {
      if (i + 1 >= argc) {
        std::cerr << "Error: -e requires an argument\n";
        return 1;
      }
      target_ext = argv[++i];
    } else if (arg == "-a") {
      all_files = true;
    } else if (arg == "--max-depth" || arg == "-d") {
      if (i + 1 >= argc) {
        std::cerr << "Error: --max-depth requires a number\n";
        return 1;
      }
      max_depth = std::stoi(argv[++i]);
    } else if (arg == "--min-size") {
      if (i + 1 >= argc) {
        std::cerr << "Error: --min-size requires a value (e.g., 100mb)\n";
        return 1;
      }
      min_size = parse_size(argv[++i]);
    } else if (arg == "--max-size") {
      if (i + 1 >= argc) {
        std::cerr << "Error: --max-size requires a value (e.g., 100mb)\n";
        return 1;
      }
      max_size = parse_size(argv[++i]);
    } else if (arg == "-j" || arg == "--json") {
      output_json = true;
    } else if (arg == "-u" || arg == "--unrestricted") {
      ignore_hidden = false;
    } else {
      target_path = arg;
    }
  }

  // If only a path is given, default to listing all files (like `ls`)
  if (target_ext.empty() && !all_files) {
    all_files = true;
  }

  try {
    std::vector<sniff::Entry> results;

    if (all_files) {
      results = sniff::find(target_path, max_depth, min_size, max_size, ignore_hidden);
    } else {
      results = sniff::glob_find(target_path, target_ext, max_depth,
                                 min_size, max_size, ignore_hidden);
    }

    if (results.empty()) {
      std::cout << "No files found.\n";
      return 0;
    }

    if (output_json) {
      json j_array = json::array();
      for (const auto &entry : results) {
        j_array.push_back({
            {"path", entry.path},
            {"size_bytes", entry.size_bytes},
            {"is_directory", entry.is_directory}
        });
      }
      std::cout << j_array.dump(2) << '\n';
    } else {
      for (const auto &entry : results) {
        std::cout << entry.path;
        if (!entry.is_directory) {
          std::cout << "\tSize: " << entry.size_bytes << " bytes";
        }
        std::cout << '\n';
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 1;
  }

  return 0;
}
