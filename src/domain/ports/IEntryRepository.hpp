#pragma once
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../model/CancellationToken.hpp"
#include "../model/FilterSpec.hpp"
#include "../model/IEntry.hpp"

namespace domain {

/* Secondary port: streams raw entries (metadata resolved, but not filtered).
   Implemented by the infrastructure scanner; faked in application tests. */
class IEntryRepository {
public:
    virtual ~IEntryRepository() = default;

    /* If the sink returns false (early stop / cancellation), traversal stops;
       the sink then owns the entry and may drop it. */
    using Sink = std::function<bool(std::unique_ptr<IEntry> entry, int depth)>;

    virtual void scan(const std::vector<std::string>& paths,
                      const FilterSpec& spec,
                      const Sink& sink,
                      CancellationToken& token) const = 0;
};

}  // namespace domain