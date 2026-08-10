#include "JsonFormatter.hpp"

#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "Formatting.hpp"

namespace {

std::string escapeJson(const std::string& raw) {
    std::string escaped;
    escaped.reserve(raw.size() + 8);
    for (const char ch : raw) {
        switch (ch) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x",
                                  static_cast<unsigned int>(ch));
                    escaped += buffer;
                } else {
                    escaped += ch;
                }
        }
    }
    return escaped;
}

std::string typeName(domain::EntryType type) {
    switch (type) {
        case domain::EntryType::FILE: return "file";
        case domain::EntryType::DIRECTORY: return "directory";
        case domain::EntryType::SYMLINK: return "symlink";
    }
    return "unknown";
}

void writeStringField(std::ostream& out, const char* label, const std::string& value) {
    out << "      \"" << label << "\": \"" << escapeJson(value) << "\",\n";
}

}  // namespace

std::string JsonFormatter::formatEntries(
    const std::vector<std::unique_ptr<domain::IEntry>>& entries) const {
    std::ostringstream out;
    out << "{\n  \"entries\": [";
    if (entries.empty()) {
        out << "]\n}\n";
        return out.str();
    }
    out << '\n';

    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        out << "    {\n";
        writeStringField(out, "name", entry->getName());
        writeStringField(out, "path", entry->getPath());
        writeStringField(out, "type", typeName(entry->getType()));
        out << "      \"size\": " << entry->getSizeBytes() << ",\n";
        writeStringField(out, "created", formatting::formatDateTime(entry->getCreatedAt()));
        writeStringField(out, "modified", formatting::formatDateTime(entry->getModifiedAt()));
        out << "      \"hidden\": " << (entry->isHidden() ? "true" : "false") << '\n';
        out << "    }" << (i + 1 == entries.size() ? "" : ",") << '\n';
    }

    out << "  ]\n}\n";
    return out.str();
}