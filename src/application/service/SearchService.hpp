#pragma once
#include "../../domain/ports/IEntryRepository.hpp"
#include "../port/ISearchService.hpp"

namespace application {

/* Orchestrates: filter-chain build -> repository scan (streaming, with
   cancellation and progress) -> sort -> result DTO. */
class SearchService : public ISearchService {
public:
    explicit SearchService(const domain::IEntryRepository& repository);

    QueryResult search(const ScanConfig& config,
                       domain::CancellationToken& token) const override;

private:
    const domain::IEntryRepository& m_repository;
};

}  // namespace application