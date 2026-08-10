#include "SearchService.hpp"

#include <chrono>
#include <memory>

#include "../../domain/service/FilterFactory.hpp"
#include "../../domain/service/Sorter.hpp"
#include "../dto/QueryResult.hpp"

namespace application {

namespace {

constexpr std::size_t PROGRESS_ENTRY_THRESHOLD = 1024;
constexpr auto PROGRESS_TIME_THRESHOLD = std::chrono::milliseconds(50);

void reportProgress(const std::optional<ProgressCallback>& callback,
                    std::uint64_t scanned,
                    const std::string& currentPath,
                    std::uint64_t& lastReported,
                    std::chrono::steady_clock::time_point& lastReportTime,
                    std::chrono::steady_clock::time_point now) {
    if (!callback) return;
    if (scanned - lastReported < PROGRESS_ENTRY_THRESHOLD &&
        now - lastReportTime < PROGRESS_TIME_THRESHOLD) {
        return;
    }
    lastReported = scanned;
    lastReportTime = now;
    (*callback)(scanned, currentPath);
}

}  // namespace

SearchService::SearchService(const domain::IEntryRepository& repository)
    : m_repository(repository) {}

QueryResult SearchService::search(const ScanConfig& config,
                                  domain::CancellationToken& token) const {
    QueryResult result;
    QueryResultStats& stats = result.stats;

    const FilterSpec spec = config.specs.empty() ? FilterSpec{} : config.specs.front();
    domain::FilterChain chain = domain::FilterFactory::createChain(config.pattern, spec);

    const auto start = std::chrono::steady_clock::now();
    std::uint64_t lastReported = 0;
    auto lastReportTime = start;

    const std::vector<std::string> paths =
        config.paths.empty() ? std::vector<std::string>{"."} : config.paths;

    for (const auto& path : paths) {
        if (token.isStopped()) break;

        m_repository.scan(
            {path}, spec,
            [&](std::unique_ptr<domain::IEntry> entry, int depth) {
                if (token.isStopped()) return false;

                ++stats.scanned;
                reportProgress(config.on_progress, stats.scanned, entry->getPath(),
                               lastReported, lastReportTime,
                               std::chrono::steady_clock::now());

                if (!chain.matches(*entry, depth)) return true;

                ++stats.matches;
                stats.total_size += entry->getSizeBytes();
                switch (entry->getType()) {
                    case domain::EntryType::FILE:
                        ++stats.file_count;
                        break;
                    case domain::EntryType::DIRECTORY:
                        ++stats.dir_count;
                        break;
                    case domain::EntryType::SYMLINK:
                        ++stats.symlink_count;
                        break;
                }
                result.entries.push_back(std::move(entry));
                return true;
            },
            token);
    }

    if (config.on_progress && stats.scanned > lastReported) {
        (*config.on_progress)(stats.scanned, "");
    }

    domain::Sorter sorter;
    sorter.sort(result.entries);

    stats.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    result.aborted = token.isStopped();
    return result;
}

}  // namespace application