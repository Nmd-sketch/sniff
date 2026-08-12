#pragma once

#include "../../domain/ports/IEntryRepository.hpp"

namespace infrastructure {

/* Streaming filesystem scanner backed by the Win32 directory API. */
class Win32Scanner : public domain::IEntryRepository {
public:
    void scan(const std::vector<std::string>& paths,
              const FilterSpec& spec,
              const Sink& sink,
              domain::CancellationToken& token) const override;
};

}  // namespace infrastructure