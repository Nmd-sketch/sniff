add_library(domain_layer STATIC
    model/CaseMode.hpp
    model/DomainEntry.hpp
    model/EntryType.hpp
    model/FileType.hpp
    model/FilterSpec.hpp
    model/IEntry.hpp
    model/MatchMode.hpp
    model/Path.hpp

    ports/IEntryRepository.hpp
    ports/IFilter.hpp
    ports/ISearchService.hpp

    service/FilterChain.cpp
    service/FilterFactory.cpp
    service/Matcher.cpp
    service/SearchService.cpp
    service/Sorter.cpp

    service/filters/DateFilter.cpp
    service/filters/DepthFilter.cpp
    service/filters/ExtensionFilter.cpp
    service/filters/HiddenFilter.cpp
    service/filters/NameFilter.cpp
    service/filters/SizeFilter.cpp
)

target_include_directories(domain_layer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})