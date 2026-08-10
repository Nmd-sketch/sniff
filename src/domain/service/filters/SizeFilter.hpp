#pragma once
#include <cstdint>
#include <optional>

#include "../../ports/IFilter.hpp"

namespace domain {

class SizeFilter : public IFilter {
public:
    SizeFilter(std::optional<std::uintmax_t> minSize,
               std::optional<std::uintmax_t> maxSize);

    bool matches(const IEntry& entry, int depth) const override;

private:
    const std::optional<std::uintmax_t> m_minSize;
    const std::optional<std::uintmax_t> m_maxSize;
};

}  // namespace domain