#include "Sorter.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace domain {

namespace {

std::string lower(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    for (const char c : text) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

}  // namespace

void Sorter::sort(std::vector<std::unique_ptr<IEntry>>& entries) const {
    std::stable_sort(entries.begin(), entries.end(),
                     [](const std::unique_ptr<IEntry>& left,
                        const std::unique_ptr<IEntry>& right) {
                         return lower(left->getPath()) < lower(right->getPath());
                     });
}

}  // namespace domain