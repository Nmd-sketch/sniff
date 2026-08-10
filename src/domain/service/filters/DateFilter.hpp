#pragma once
#include <chrono>
#include <optional>
#include <string>

#include "../../ports/IFilter.hpp"

namespace domain {

/* Owns date parsing: --*-within takes a relative duration ("2d", "30m", "90s"),
   --*-before takes an absolute datetime ("2024-01-31" or "2024-01-31 12:30:00").
   Invalid values throw std::invalid_argument at construction. */
class DateFilter : public IFilter {
public:
    DateFilter(std::optional<std::string> modifiedWithin,
               std::optional<std::string> modifiedBefore,
               std::optional<std::string> createdWithin,
               std::optional<std::string> createdBefore);

    bool matches(const IEntry& entry, int depth) const override;

private:
    const std::chrono::system_clock::time_point m_now;
    const std::optional<std::chrono::seconds> m_modifiedWithin;
    const std::optional<std::chrono::system_clock::time_point> m_modifiedBefore;
    const std::optional<std::chrono::seconds> m_createdWithin;
    const std::optional<std::chrono::system_clock::time_point> m_createdBefore;
};

}  // namespace domain