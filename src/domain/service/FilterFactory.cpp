#include "FilterFactory.hpp"

#include <memory>

#include "filters/DateFilter.hpp"
#include "filters/DepthFilter.hpp"
#include "filters/ExcludeFilter.hpp"
#include "filters/ExtensionFilter.hpp"
#include "filters/HiddenFilter.hpp"
#include "filters/NameFilter.hpp"
#include "filters/SizeFilter.hpp"
#include "filters/TypeFilter.hpp"

namespace domain {

FilterChain FilterFactory::createChain(const std::string& pattern,
                                       const FilterSpec& spec) {
    std::vector<std::unique_ptr<IFilter>> filters;

    if (!pattern.empty()) {
        filters.push_back(std::make_unique<NameFilter>(
            pattern, spec.match_mode.value_or(MatchMode::REGEX),
            spec.case_mode.value_or(CaseMode::SENSITIVE),
            spec.full_path.value_or(false)));
    }

    /* Hidden entries are hidden from results unless --hidden was given. */
    filters.push_back(
        std::make_unique<HiddenFilter>(spec.detect_hidden.value_or(false)));

    if (spec.types) {
        filters.push_back(std::make_unique<TypeFilter>(*spec.types));
    }

    if (spec.extension) {
        filters.push_back(std::make_unique<ExtensionFilter>(*spec.extension));
    }

    if (spec.min_size || spec.max_size) {
        filters.push_back(std::make_unique<SizeFilter>(spec.min_size, spec.max_size));
    }

    if (spec.min_depth || spec.max_depth) {
        filters.push_back(
            std::make_unique<DepthFilter>(spec.min_depth, spec.max_depth));
    }

    if (spec.modified_within || spec.modified_before || spec.created_within ||
        spec.created_before) {
        filters.push_back(std::make_unique<DateFilter>(
            spec.modified_within, spec.modified_before, spec.created_within,
            spec.created_before));
    }

    if (spec.exclude) {
        filters.push_back(std::make_unique<ExcludeFilter>(*spec.exclude));
    }

    return FilterChain(std::move(filters));
}

}  // namespace domain