#include <iostream>
#include <string>
#include <vector>

#include "interface/cli/CommandParser.hpp"

namespace {

const char* toText(MatchMode mode) {
    switch (mode) {
        case MatchMode::REGEX: return "regex";
        case MatchMode::GLOB: return "glob";
        case MatchMode::FIXED: return "fixed-strings";
    }
    return "?";
}

const char* toText(CaseMode mode) {
    switch (mode) {
        case CaseMode::SENSITIVE: return "sensitive";
        case CaseMode::INSENSITIVE: return "insensitive";
    }
    return "?";
}

const char* toText(FileType type) {
    switch (type) {
        case FileType::FILE: return "file";
        case FileType::DIRECTORY: return "directory";
        case FileType::SYMLINK: return "symlink";
        case FileType::EXECUTABLE: return "executable";
        case FileType::EMPTY: return "empty";
    }
    return "?";
}

const char* toText(FormatType format) {
    switch (format) {
        case FormatType::JSON: return "json";
        case FormatType::TREE: return "tree";
        case FormatType::TABLE: return "table";
    }
    return "?";
}

void printList(const char* label, const std::vector<std::string>& values) {
    if (values.empty()) return;
    std::cout << label;
    for (const auto& value : values) {
        std::cout << ' ' << value;
    }
    std::cout << '\n';
}

void printSpec(const FilterSpec& spec) {
    if (spec.extension) printList("extension:   ", *spec.extension);
    if (spec.exclude) printList("exclude:     ", *spec.exclude);
    if (spec.types) {
        std::cout << "types:       ";
        for (std::size_t i = 0; i < spec.types->size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << toText((*spec.types)[i]);
        }
        std::cout << '\n';
    }
    if (spec.min_size) std::cout << "min size:    " << *spec.min_size << " bytes\n";
    if (spec.max_size) std::cout << "max size:    " << *spec.max_size << " bytes\n";
    if (spec.detect_hidden) std::cout << "hidden:      yes\n";
    if (spec.follow_symlinks) std::cout << "follow:      yes\n";
    if (spec.full_path) std::cout << "full path:   yes\n";
    if (spec.match_mode) std::cout << "match mode:  " << toText(*spec.match_mode) << '\n';
    if (spec.case_mode) std::cout << "case mode:   " << toText(*spec.case_mode) << '\n';
    if (spec.min_depth) std::cout << "min depth:   " << *spec.min_depth << '\n';
    if (spec.max_depth) std::cout << "max depth:   " << *spec.max_depth << '\n';
    if (spec.modified_within) std::cout << "modified within:  " << *spec.modified_within << '\n';
    if (spec.modified_before) std::cout << "modified before:  " << *spec.modified_before << '\n';
    if (spec.created_within) std::cout << "created within:   " << *spec.created_within << '\n';
    if (spec.created_before) std::cout << "created before:   " << *spec.created_before << '\n';
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    CommandParser parser;
    if (!parser.parse(args)) {
        std::cerr << "sniff: " << parser.lastError() << '\n';
        return 1;
    }

    const auto& commands = parser.getCommands();
    if (commands.empty()) {
        std::cout << "pattern:     (none)\n";
    } else {
        std::cout << "pattern:     " << commands[0] << '\n';
        for (std::size_t i = 1; i < commands.size(); ++i) {
            std::cout << "path:        " << commands[i] << '\n';
        }
    }
    std::cout << "format:      " << toText(parser.getFormatType()) << '\n';
    for (const auto& spec : parser.getFilterSpecs()) {
        printSpec(spec);
    }
    return 0;
}
