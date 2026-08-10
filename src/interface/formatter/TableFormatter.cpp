#include "TableFormatter.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "Formatting.hpp"

namespace {

std::string typeChar(domain::EntryType type) {
    switch (type) {
        case domain::EntryType::FILE: return "f";
        case domain::EntryType::DIRECTORY: return "d";
        case domain::EntryType::SYMLINK: return "l";
    }
    return "?";
}

void writeRow(std::ostream& out, const std::string& type, const std::string& name,
              const std::string& size, const std::string& modified, std::size_t width_type,
              std::size_t width_name, std::size_t width_size) {
    out << std::left << std::setw(width_type) << type << "  "
        << std::setw(width_name) << name << "  "
        << std::setw(width_size) << size << "  "
        << modified << '\n';
}

}  // namespace

std::string TableFormatter::formatEntries(
    const std::vector<std::unique_ptr<domain::IEntry>>& entries) const {
    if (entries.empty()) return {};

    std::vector<std::string> types;
    std::vector<std::string> names;
    std::vector<std::string> sizes;
    std::vector<std::string> dates;
    types.reserve(entries.size());
    names.reserve(entries.size());
    sizes.reserve(entries.size());
    dates.reserve(entries.size());

    std::size_t width_type = 4;
    std::size_t width_name = 4;
    std::size_t width_size = 4;
    std::size_t width_date = 8;

    for (const auto& entry : entries) {
        types.push_back(typeChar(entry->getType()));
        names.push_back(entry->getName());
        sizes.push_back(entry->getType() == domain::EntryType::FILE
                            ? formatting::humanReadableSize(entry->getSizeBytes())
                            : "-");
        dates.push_back(formatting::formatDateTime(entry->getModifiedAt()));

        width_type = std::max(width_type, types.back().size());
        width_name = std::max(width_name, names.back().size());
        width_size = std::max(width_size, sizes.back().size());
        width_date = std::max(width_date, dates.back().size());
    }

    std::ostringstream out;
    writeRow(out, "TYPE", "NAME", "SIZE", "MODIFIED", width_type, width_name, width_size);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        writeRow(out, types[i], names[i], sizes[i], dates[i], width_type, width_name, width_size);
    }
    return out.str();
}