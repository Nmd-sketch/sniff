#include "Sorter.hpp"

#include <algorithm>
#include <cctype>
#include <numeric>
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
    const std::size_t count = entries.size();
    if (count < 2) return;

    /* Decorate-sort-undecorate: lower-case each path once up front instead of
       inside every comparison (which allocated two strings per comparison). */
    std::vector<std::string> keys;
    keys.reserve(count);
    for (const auto& entry : entries) {
        keys.push_back(lower(entry->getPath()));
    }

    std::vector<std::size_t> order(count);
    std::iota(order.begin(), order.end(), std::size_t{0});
    std::stable_sort(order.begin(), order.end(),
                     [&keys](std::size_t left, std::size_t right) {
                         return keys[left] < keys[right];
                     });

    std::vector<std::unique_ptr<IEntry>> reordered;
    reordered.reserve(count);
    for (const std::size_t index : order) {
        reordered.push_back(std::move(entries[index]));
    }
    entries.swap(reordered);
}

}  // namespace domain