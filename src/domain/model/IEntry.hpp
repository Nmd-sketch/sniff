#pragma once
#include <chrono>
#include <cstdint>
#include <string>

#include "EntryType.hpp"

namespace domain {

struct IEntry {
    virtual const std::string& getName() const = 0;
    virtual const std::string& getPath() const = 0;
    virtual EntryType getType() const = 0;
    virtual bool isHidden() const = 0;
    virtual bool isExecutable() const = 0;
    virtual std::uintmax_t getSizeBytes() const = 0;
    virtual const std::chrono::system_clock::time_point& getCreatedAt() const = 0;
    virtual const std::chrono::system_clock::time_point& getModifiedAt() const = 0;
    virtual ~IEntry() = default;
};

}  // namespace domain