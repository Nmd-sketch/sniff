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

}  // namespace

ExcludeFilter::ExcludeFilter(std::vector<std::string> patterns)
    : m_patterns(std::move(patterns)) {
    for (auto& pattern : m_patterns) {
        pattern = lower(pattern);
    }
}

bool ExcludeFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    const std::string path = lower(entry.getPath());
    for (const auto& pattern : m_patterns) {
        if (path.find(pattern) != std::string::npos) {
            return false;
        }
    }
    return true;
}

}  // namespace domain