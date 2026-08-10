#include "ExtensionFilter.hpp"

#include <algorithm>
#include <cctype>

namespace domain {

namespace {

std::string normalizedExtension(const std::string& name) {
    const std::size_t dot = name.find_last_of('.');
    std::string extension = (dot == std::string::npos) ? std::string()
                                                       : name.substr(dot + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return extension;
}

}  // namespace

ExtensionFilter::ExtensionFilter(std::vector<std::string> extensions)
    : m_extensions(std::move(extensions)) {
    for (auto& extension : m_extensions) {
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }
}

bool ExtensionFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    const std::string extension = normalizedExtension(entry.getName());
    return std::find(m_extensions.begin(), m_extensions.end(), extension) !=
           m_extensions.end();
}

}  // namespace domain