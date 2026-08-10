#pragma once
#include <vector>

#include "../../ports/IFilter.hpp"
#include "../../model/FileType.hpp"

namespace domain {

class TypeFilter : public IFilter {
public:
    explicit TypeFilter(std::vector<FileType> types);

    bool matches(const IEntry& entry, int depth) const override;

private:
    const std::vector<FileType> m_types;
};

}  // namespace domain