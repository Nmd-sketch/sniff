#include "ExcludeFilter.hpp"

#include <algorithm>
#include <cctype>

namespace domain {

namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

/* Case-insensitive substring search without a lower-cased copy of the path
   (the old lower(path) allocated one for every scanned entry). */
bool containsCaseInsensitive(const std::string& text, const std::string& pattern) {
    if (pattern.empty()) return true;
    return std::search(text.begin(), text.end(), pattern.begin(), pattern.end(),
                       [](char lhs, char rhs) {
                           return std::tolower(static_cast<unsigned char>(lhs)) ==
                                  std::tolower(static_cast<unsigned char>(rhs));
                       }) != text.end();
}

}  // namespace

ExcludeFilter::ExcludeFilter(std::vector<std::string> patterns)
    : m_patterns(std::move(patterns)) {
    for (auto& pattern : m_patterns) {
        pattern = lower(pattern);
    }
}

bool ExcludeFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    const std::string& path = entry.getPath();
    for (const auto& pattern : m_patterns) {
        if (containsCaseInsensitive(path, pattern)) {
            return false;
        }
    }
    return true;
}

}  // namespace domain