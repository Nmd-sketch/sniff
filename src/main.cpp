#include "../include/core.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <ranges>
#include <string>
#include <string_view>
using json = nlohmann::json;

void print_help() {
  std::cout << "Usage: sniff [OPTIONS] [PATH]\n"
            << "\n"
            << "Options:\n"
            << "\t-a\tScans all files and directories in the selected path\n"
            << "\t-e <ext>\tFind files by extension (e.g., -e cpp or -e .cpp)\n"
            << "\t-h\tShow this help message\n"
            << "\t-d\tSets the maximum directory depth (defaults to -1 if "
               "number < -1)\n"
            << "\t--min-size\tSets the minimum file size (e.g., 100mb, 400kb)\n"
            << "\t--max-size\tSets the maximum file size (e.g., 100mb, 400kb)\n"
            << "\t--json\tDisplays the output as json\n"
            << "\t--unrestricted\t Displays hidden files and directories"
            << "\n"
            << "If no path is provided, defaults to '.' (current directory)\n";
}

// Helper function to parse the size of the input
std::uintmax_t parse_size(std::string_view input) {
  // Reusable predicate for checking digits
  auto is_digit = [](unsigned char c) { return std::isdigit(c); };

  // We take a view up to the last number
  auto num_view = input | std::views::take_while(is_digit);

  // We take a view of the suffix
  auto suffix_view =
      input | std::views::drop_while(is_digit) |
      std::views::transform([](unsigned char c) { return std::tolower(c); });

  // Now we extract the number
  std::uintmax_t number = 0;
  if (!num_view.empty()) {
    std::string s;
    std::ranges::copy(num_view, std::back_inserter(s));
    number = std::stoull(s);
  }

  // Compare the suffix using ranges::equal
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

  // If no suffix we just assume raw bytes
  return number;
}

int main(int argc, char *argv[]) {

  // Setup of default values if nothing
  // is passed to sniff
  std::string_view target_path = ".";
  std::string_view target_ext = "";
  bool all_files = false;
  int max_depth = -1;
  std::uintmax_t min_size = 0;
  std::uintmax_t max_size = std::numeric_limits<std::uintmax_t>::max();
  bool output_json = false;
  bool ignore_hidden = true;

  // Simple argument parser
  for (int i = 1; i < argc; ++i) {
    std::string_view arg = argv[i];

    // If -h then we execute the help command
    if (arg == "-h" || arg == "-help") {
      print_help();
      return 0;
    }

    // If -e then we do a search by extension
    else if (arg == "-e") {
      // We make sure that an extension is provided
      // If not then we write an error to std::cerr
      if (i + 1 >= argc) {
        std::cerr << "Error: -e requires an argument" << '\n';
        return 1;
      }

      target_ext = argv[++i]; // Here we grab the extension
    }

    else if (arg == "-a") {
      // We signal we want all files setting the boolean to true
      all_files = true;
    }
    // If -depth then we set up the max recursion depth
    else if (arg == "--max-depth" || arg == "-d") {
      // We make sure that a max recursion depth is given
      // if not then we use the default -1 value
      // for max recursion.
      // NOTE: If the default value is less than -1 max recursion is used
      if (i + 1 >= argc) {
        std::cerr << "Error: --max-depth requires a number\n";
        return 1;
      }
      max_depth = std::stoi(argv[++i]);
    } else if (arg == "--min-size") {
      if (i + 1 >= argc) {
        std::cerr << "Error: --min-size requires a value (e.g., 100mb)";
        return 1;
      }
      min_size = parse_size(argv[++i]);
    } else if (arg == "--max-size") {
      if (i + 1 >= argc) {
        std::cerr << "Error: --Max-size requires a value (e.g., 100mb)";
        return 1;
      }
      max_size = parse_size(argv[++i]);
    } else if (arg == "-j" || arg == "--json") {
      output_json = true;
    } else if (arg == "-u" || arg == "--unrestricted") {
      ignore_hidden = false;
    }

    else {
      // If it's not a flag then must be the path
      target_path = arg;
    }
  }

  if (target_ext.empty() && !all_files) {
    std::cerr << "Error: You must provide an extension using -e\n";
    std::cerr << "Run 'sniff -h' for usage information.\n";
    return 1;
  }

  // Now we execute the engine after having all our args parsed
  // std::filesystem::path is used to handle cleanly the conversion
  std::filesystem::path search_dir(target_path);

  try {
    // If we are targeting every extension
    // then we perform a normal search for every
    // file and directory available
    if (target_ext.empty() && all_files == true) {
      auto results = sniff::find(search_dir, max_depth, min_size, max_size, ignore_hidden);

      // If --json || -j flag is set
      if (output_json) {
        json j_array = json::array();
	// We push the attributes of each Entry into j_array
        for (const auto &entry : results) {
          j_array.push_back({{"path", entry.path.string()},
                             {"size_bytes", entry.size_bytes}});
        }
        std::cout << j_array.dump(2) << '\n';
      }

      else {
        // For each entry we print in console the path
        // the size if it's not a directory
        for (const auto &entry : results) {
          std::cout << entry.path;
          if (!entry.is_directory) {
            std::cout << "\tSize: " << entry.size_bytes << " bytes\n";
          } else {
            std::cout << '\n';
          }
        }
      }

    }

    // If we are searching by extension then we use glob_find to
    // perform a search by wildcard
    else {
      auto results = sniff::glob_find(search_dir, target_ext, max_depth,
                                      min_size, max_size, ignore_hidden);
      if (output_json) {
        json j_array = json::array();
        for (const auto &entry : results) {
          j_array.push_back({{"path", entry.path.string()},
                             {"size_bytes", entry.size_bytes}});
        }
        std::cout << j_array.dump(2) << '\n';
      }

      else {
        // For each entry we print the path and size
        for (const auto &entry : results) {
          std::cout << entry.path << "\tSize: " << entry.size_bytes
                    << " bytes\n";
        }
      }
    }
  } catch (const std::filesystem::filesystem_error &e) {
    // Here we handle filesystem errors gracefully
    // so the program keeps running even if it hits
    // an invalid path or gets permission errors
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  return 0;
}
