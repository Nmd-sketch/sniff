#pragma once
#include "../../domain/model/CancellationToken.hpp"
#include "../dto/QueryResult.hpp"
#include "../dto/ScanConfig.hpp"

namespace application {

class ISearchService {
public:
    virtual ~ISearchService() = default;

    virtual QueryResult search(const ScanConfig& config,
                               domain::CancellationToken& token) const = 0;
};

}  // namespace application