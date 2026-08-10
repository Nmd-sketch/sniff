#include "TypeFilter.hpp"

#include <algorithm>

namespace domain {

TypeFilter::TypeFilter(std::vector<FileType> types) : m_types(std::move(types)) {}

bool TypeFilter::matches(const IEntry& entry, int depth) const {
    (void)depth;
    if (entry.getType() == EntryType::SYMLINK) {
        return std::find(m_types.begin(), m_types.end(), FileType::SYMLINK) !=
               m_types.end();
    }
    if (entry.getType() == EntryType::DIRECTORY) {
        return std::find(m_types.begin(), m_types.end(), FileType::DIRECTORY) !=
               m_types.end();
    }
    /* A regular file can simultaneously be EMPTY and/or EXECUTABLE. */
    if (std::find(m_types.begin(), m_types.end(), FileType::FILE) != m_types.end()) {
        return true;
    }
    if (entry.isExecutable() &&
        std::find(m_types.begin(), m_types.end(), FileType::EXECUTABLE) != m_types.end()) {
        return true;
    }
    if (entry.getSizeBytes() == 0 &&
        std::find(m_types.begin(), m_types.end(), FileType::EMPTY) != m_types.end()) {
        return true;
    }
    return false;
}

}  // namespace domain