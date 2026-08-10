#include "CommandParser.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <optional>

namespace {

    std::string toLower(std::string text) {
        std::transform(text.begin(), text.end(), text.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return text;
    }

    bool parseSize(const std::string& value,
                   std::optional<std::uintmax_t>& out_min,
                   std::optional<std::uintmax_t>& out_max,
                   std::string& error) {
        error.clear();

        std::size_t pos = 0;
        bool is_min = false;
        bool is_max = false;
        if (pos < value.size() && (value[pos] == '+' || value[pos] == '-')) {
            is_min = (value[pos] == '+');
            is_max = !is_min;
            ++pos;
        }

        const std::size_t number_start = pos;
        while (pos < value.size() &&
               (std::isdigit(static_cast<unsigned char>(value[pos])) || value[pos] == '.')) {
            ++pos;
        }
        if (pos == number_start) {
            error = "invalid size '" + value + "' (expected [+-]NUM[UNIT], e.g. +10M or -1G)";
            return false;
        }

        const std::string number_part = value.substr(number_start, pos - number_start);
        const std::string unit_part = toLower(value.substr(pos));

        char* end = nullptr;
        const double number = std::strtod(number_part.c_str(), &end);
        if (end != number_part.c_str() + number_part.size()) {
            error = "invalid size '" + value + "'";
            return false;
        }

        double multiplier = 1.0;
        if (!unit_part.empty()) {
            if (unit_part == "b") multiplier = 1.0;
            else if (unit_part == "k") multiplier = 1e3;
            else if (unit_part == "m") multiplier = 1e6;
            else if (unit_part == "g") multiplier = 1e9;
            else if (unit_part == "t") multiplier = 1e12;
            else if (unit_part == "ki") multiplier = 1024.0;
            else if (unit_part == "mi") multiplier = 1024.0 * 1024.0;
            else if (unit_part == "gi") multiplier = 1024.0 * 1024.0 * 1024.0;
            else if (unit_part == "ti") multiplier = 1024.0 * 1024.0 * 1024.0 * 1024.0;
            else {
                error = "invalid size unit '" + unit_part + "' in '" + value + "'";
                return false;
            }
        }

        const double bytes = number * multiplier;
        if (!std::isfinite(bytes) ||
            bytes > static_cast<double>(std::numeric_limits<std::uintmax_t>::max())) {
            error = "size '" + value + "' is too large";
            return false;
        }

        const std::uintmax_t size = static_cast<std::uintmax_t>(std::round(bytes));
        if (is_min) {
            out_min = size;
        } else if (is_max) {
            out_max = size;
        } else {
            out_min = size;
            out_max = size;
        }
        return true;
    }

    bool parseDepth(const std::string& value, int& out, std::string& error) {
        error.clear();

        std::size_t pos = 0;
        if (pos < value.size() && value[pos] == '+') {
            ++pos;
        }
        if (pos == value.size()) {
            error = "invalid depth '" + value + "' (expected a non-negative integer)";
            return false;
        }
        for (; pos < value.size(); ++pos) {
            if (!std::isdigit(static_cast<unsigned char>(value[pos]))) {
                error = "invalid depth '" + value + "' (expected a non-negative integer)";
                return false;
            }
        }
        try {
            const long parsed = std::stol(value);
            if (parsed < 0 || parsed > std::numeric_limits<int>::max()) {
                error = "invalid depth '" + value + "' (expected a non-negative integer)";
                return false;
            }
            out = static_cast<int>(parsed);
            return true;
        } catch (const std::exception&) {
            error = "invalid depth '" + value + "' (expected a non-negative integer)";
            return false;
        }
    }

    bool parseType(const std::string& value, FileType& out, std::string& error) {
        error.clear();

        const std::string key = toLower(value);
        if (key == "f" || key == "file") out = FileType::FILE;
        else if (key == "d" || key == "dir" || key == "directory") out = FileType::DIRECTORY;
        else if (key == "l" || key == "symlink") out = FileType::SYMLINK;
        else if (key == "x" || key == "executable") out = FileType::EXECUTABLE;
        else if (key == "e" || key == "empty") out = FileType::EMPTY;
        else {
            error = "invalid type '" + value + "' (expected f, d, l, x or e)";
            return false;
        }
        return true;
    }

    bool parseFormat(const std::string& value, FormatType& out, std::string& error) {
        error.clear();

        const std::string key = toLower(value);
        if (key == "tree") out = FormatType::TREE;
        else if (key == "table") out = FormatType::TABLE;
        else if (key == "json") out = FormatType::JSON;
        else {
            error = "invalid format '" + value + "' (expected tree, table or json)";
            return false;
        }
        return true;
    }

    bool applyValueOption(const std::string& name,
                          const std::string& value,
                          FilterSpec& spec,
                          FormatType& format,
                          std::string& error) {
        if (name == "type") {
            FileType type;
            if (!parseType(value, type, error)) return false;
            if (!spec.types) spec.types.emplace();
            spec.types->push_back(type);
        } else if (name == "extension") {
            std::string ext = value;
            if (ext.size() > 1 && ext.front() == '.') ext.erase(0, 1);
            if (!spec.extension) spec.extension.emplace();
            spec.extension->push_back(std::move(ext));
        } else if (name == "exclude") {
            if (!spec.exclude) spec.exclude.emplace();
            spec.exclude->push_back(value);
        } else if (name == "max-depth") {
            int depth = 0;
            if (!parseDepth(value, depth, error)) return false;
            spec.max_depth = depth;
        } else if (name == "min-depth") {
            int depth = 0;
            if (!parseDepth(value, depth, error)) return false;
            spec.min_depth = depth;
        } else if (name == "size") {
            std::optional<std::uintmax_t> min_size;
            std::optional<std::uintmax_t> max_size;
            if (!parseSize(value, min_size, max_size, error)) return false;
            if (min_size) spec.min_size = min_size;
            if (max_size) spec.max_size = max_size;
        } else if (name == "changed-within") {
            spec.modified_within = value;
        } else if (name == "changed-before") {
            spec.modified_before = value;
        } else if (name == "created-within") {
            spec.created_within = value;
        } else if (name == "created-before") {
            spec.created_before = value;
        } else if (name == "format") {
            if (!parseFormat(value, format, error)) return false;
        } else {
            error = "unknown option '--" + name + "'";
            return false;
        }
        return true;
    }

}  // namespace

bool CommandParser::parse(const std::vector<std::string>& args) {
    m_filter_specs.clear();
    m_commands.clear();
    m_last_error.clear();
    m_format_type = FormatType::TABLE;

    FilterSpec spec;
    std::vector<std::string> positionals;
    bool options_end = false;

    auto apply_match_mode = [&](MatchMode mode) -> bool {
        if (spec.match_mode && *spec.match_mode != mode) {
            m_last_error = "conflicting matching options (--glob vs --fixed-strings)";
            return false;
        }
        spec.match_mode = mode;
        return true;
    };
    auto apply_case_mode = [&](CaseMode mode) -> bool {
        if (spec.case_mode && *spec.case_mode != mode) {
            m_last_error = "conflicting case options (--ignore-case vs --case-sensitive)";
            return false;
        }
        spec.case_mode = mode;
        return true;
    };

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& token = args[i];

        if (options_end) {
            positionals.push_back(token);
            continue;
        }
        if (token == "--") {
            options_end = true;
            continue;
        }
        if (token.size() < 2 || token.front() != '-') {
            positionals.push_back(token);
            continue;
        }

        if (token[1] == '-') {
            std::string name = token.substr(2);
            std::string inline_value;
            bool has_inline = false;
            const std::size_t eq = name.find('=');
            if (eq != std::string::npos) {
                inline_value = name.substr(eq + 1);
                name = name.substr(0, eq);
                has_inline = true;
            }

            auto fetch_value = [&](bool allow_leading_dash) -> std::optional<std::string> {
                if (has_inline) {
                    if (inline_value.empty()) {
                        m_last_error = "option '--" + name + "' requires a value";
                        return std::nullopt;
                    }
                    return inline_value;
                }
                if (i + 1 >= args.size()) {
                    m_last_error = "option '--" + name + "' requires a value";
                    return std::nullopt;
                }
                const std::string& next = args[i + 1];
                if (!allow_leading_dash && !next.empty() && next.front() == '-') {
                    m_last_error = "option '--" + name + "' requires a value";
                    return std::nullopt;
                }
                ++i;
                return next;
            };
            auto reject_inline = [&]() -> bool {
                if (has_inline) {
                    m_last_error = "option '--" + name + "' does not take a value";
                    return false;
                }
                return true;
            };

            if (name == "hidden") {
                if (!reject_inline()) return false;
                spec.detect_hidden = true;
            } else if (name == "follow") {
                if (!reject_inline()) return false;
                spec.follow_symlinks = true;
            } else if (name == "full-path") {
                if (!reject_inline()) return false;
                spec.full_path = true;
            } else if (name == "glob") {
                if (!reject_inline() || !apply_match_mode(MatchMode::GLOB)) return false;
            } else if (name == "fixed-strings") {
                if (!reject_inline() || !apply_match_mode(MatchMode::FIXED)) return false;
            } else if (name == "ignore-case") {
                if (!reject_inline() || !apply_case_mode(CaseMode::INSENSITIVE)) return false;
            } else if (name == "case-sensitive") {
                if (!reject_inline() || !apply_case_mode(CaseMode::SENSITIVE)) return false;
            } else if (name == "type" || name == "extension" || name == "exclude" ||
                       name == "max-depth" || name == "min-depth" || name == "size" ||
                       name == "changed-within" || name == "changed-before" ||
                       name == "created-within" || name == "created-before" ||
                       name == "format") {
                const bool allow_leading_dash = (name == "size");
                std::optional<std::string> value = fetch_value(allow_leading_dash);
                if (!value) return false;
                std::string error;
                if (!applyValueOption(name, *value, spec, m_format_type, error)) {
                    m_last_error = error;
                    return false;
                }
            } else {
                m_last_error = "unknown option '--" + name + "'";
                return false;
            }
        } else {
            for (std::size_t c = 1; c < token.size(); ++c) {
                const char flag = token[c];
                switch (flag) {
                    case 'H':
                        spec.detect_hidden = true;
                        break;
                    case 'L':
                        spec.follow_symlinks = true;
                        break;
                    case 'p':
                        spec.full_path = true;
                        break;
                    case 'g':
                        if (!apply_match_mode(MatchMode::GLOB)) return false;
                        break;
                    case 'F':
                        if (!apply_match_mode(MatchMode::FIXED)) return false;
                        break;
                    case 'i':
                        if (!apply_case_mode(CaseMode::INSENSITIVE)) return false;
                        break;
                    case 's':
                        if (!apply_case_mode(CaseMode::SENSITIVE)) return false;
                        break;
                    case 't':
                    case 'e':
                    case 'E':
                    case 'd':
                    case 'S': {
                        std::string option_name;
                        switch (flag) {
                            case 't': option_name = "type"; break;
                            case 'e': option_name = "extension"; break;
                            case 'E': option_name = "exclude"; break;
                            case 'd': option_name = "max-depth"; break;
                            case 'S': option_name = "size"; break;
                            default: break;
                        }

                        std::string value;
                        if (c + 1 < token.size()) {
                            value = token.substr(c + 1);
                        } else if (i + 1 < args.size()) {
                            const std::string& next = args[i + 1];
                            const bool allow_leading_dash = (flag == 'S');
                            if (!allow_leading_dash && !next.empty() && next.front() == '-') {
                                m_last_error = "option '-" + std::string(1, flag) + "' requires a value";
                                return false;
                            }
                            value = next;
                            ++i;
                        } else {
                            m_last_error = "option '-" + std::string(1, flag) + "' requires a value";
                            return false;
                        }

                        std::string error;
                        if (!applyValueOption(option_name, value, spec, m_format_type, error)) {
                            m_last_error = error;
                            return false;
                        }
                        c = token.size();
                        break;
                    }
                    default:
                        m_last_error = "unknown option '-" + std::string(1, flag) + "'";
                        return false;
                }
            }
        }
    }

    if (spec.min_depth && spec.max_depth && *spec.min_depth > *spec.max_depth) {
        m_last_error = "--min-depth cannot be greater than --max-depth";
        return false;
    }

    m_commands = std::move(positionals);
    m_filter_specs.push_back(std::move(spec));
    return true;
}

const std::vector<FilterSpec>& CommandParser::getFilterSpecs() const {
    return m_filter_specs;
}

const std::vector<std::string>& CommandParser::getCommands() const {
    return m_commands;
}

FormatType CommandParser::getFormatType() const {
    return m_format_type;
}

const std::string& CommandParser::lastError() const {
    return m_last_error;
}
