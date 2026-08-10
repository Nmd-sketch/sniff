#pragma once
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include "IEntry.hpp"

namespace domain {

class DomainEntry : public IEntry {
public:
    DomainEntry(EntryType type, bool hidden, std::string name, std::string path,
                std::uintmax_t sizeBytes,
                std::chrono::system_clock::time_point createdAt,
                std::chrono::system_clock::time_point modifiedAt)
        : m_type(type), m_isHidden(hidden), m_name(std::move(name)), m_path(std::move(path)),
          m_sizeBytes(sizeBytes), m_createdAt(createdAt), m_modifiedAt(modifiedAt) {}

    const std::string& getName() const override {
        return m_name;
    }

    const std::string& getPath() const override {
        return m_path;
    }

    EntryType getType() const override {
        return m_type;
    }

    bool isHidden() const override {
        return m_isHidden;
    }

    std::uintmax_t getSizeBytes() const override {
        return m_sizeBytes;
    }

    const std::chrono::system_clock::time_point& getCreatedAt() const override {
        return m_createdAt;
    }

    const std::chrono::system_clock::time_point& getModifiedAt() const override {
        return m_modifiedAt;
    }

private:
    const EntryType m_type;
    const bool m_isHidden;
    const std::string m_name;
    const std::string m_path;
    const std::uintmax_t m_sizeBytes;
    const std::chrono::system_clock::time_point m_createdAt;
    const std::chrono::system_clock::time_point m_modifiedAt;
};

}  // namespace domain