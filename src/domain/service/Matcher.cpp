#include "Matcher.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace domain {

namespace {

bool isRegexSpecial(char c) {
    switch (c) {
        case '^': case '$': case '\\': case '.': case '+': case '(':
        case ')': case '|': case '{': case '}': case '/':
            return true;
        default:
            return false;
    }
}

std::string globToRegex(const std::string& glob) {
    std::string regex;
    regex.reserve(glob.size() * 2);

    bool in_class = false;
    for (const char c : glob) {
        if (c == '[' && !in_class) {
            in_class = true;
            regex += '[';
            continue;
        }
        if (c == ']' && in_class) {
            in_class = false;
            regex += ']';
            continue;
        }
        if (in_class) {
            regex += c;
            continue;
        }
        switch (c) {
            case '*': regex += ".*"; break;
            case '?': regex += "."; break;
            default:
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
                    regex += c;
                } else if (isRegexSpecial(c)) {
                    regex += '\\';
                    regex += c;
                } else {
                    regex += c;
                }
        }
    }
    /* Shell-style glob matches the whole name. */
    return "^" + regex + "$";
}

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

/* Case-insensitive substring search that never materializes a lower-cased copy
   of the text (the old lower(text).find(pattern) allocated one per entry). */
bool containsCaseInsensitive(const std::string& text, const std::string& pattern) {
    if (pattern.empty()) return true;
    return std::search(text.begin(), text.end(), pattern.begin(), pattern.end(),
                       [](char lhs, char rhs) {
                           return std::tolower(static_cast<unsigned char>(lhs)) ==
                                  std::tolower(static_cast<unsigned char>(rhs));
                       }) != text.end();
}

}  // namespace

Matcher::Matcher(std::string pattern, MatchMode mode, CaseMode caseMode)
    : m_mode(mode), m_caseMode(caseMode), m_pattern(std::move(pattern)),
      m_patternLower(m_caseMode == CaseMode::INSENSITIVE ? lower(m_pattern)
                                                         : std::string()),
      m_regex(buildRegex(m_pattern, m_mode, m_caseMode)) {}

std::regex Matcher::buildRegex(const std::string& pattern, MatchMode mode,
                               CaseMode caseMode) {
    try {
        switch (mode) {
            case MatchMode::GLOB:
                return std::regex(globToRegex(pattern),
                                  caseMode == CaseMode::INSENSITIVE
                                      ? std::regex::icase
                                      : std::regex::ECMAScript);
            case MatchMode::REGEX:
                return std::regex(pattern,
                                  caseMode == CaseMode::INSENSITIVE
                                      ? std::regex::icase
                                      : std::regex::ECMAScript);
            case MatchMode::FIXED:
                break;
        }
    } catch (const std::regex_error& error) {
        throw std::invalid_argument("invalid pattern '" + pattern + "': " +
                                    error.what());
    }
    return std::regex();
}

bool Matcher::matches(const std::string& text) const {
    if (m_mode == MatchMode::FIXED) {
        if (m_caseMode == CaseMode::INSENSITIVE) {
            return containsCaseInsensitive(text, m_patternLower);
        }
        return text.find(m_pattern) != std::string::npos;
    }
    return std::regex_search(text, m_regex);
}

}  // namespace domain