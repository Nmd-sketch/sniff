add_library(domain_layer STATIC
    model/CancellationToken.hpp
    model/CaseMode.hpp
    model/DomainEntry.hpp
    model/EntryType.hpp
    model/FileType.hpp
    model/FilterSpec.hpp
    model/IEntry.hpp
    model/MatchMode.hpp

    ports/IFilter.hpp
    ports/IEntryRepository.hpp

    service/FilterChain.cpp
    service/FilterFactory.cpp
    service/Matcher.cpp
    service/Sorter.cpp

    service/filters/DateFilter.cpp
    service/filters/DepthFilter.cpp
    service/filters/ExcludeFilter.cpp
    service/filters/ExtensionFilter.cpp
    service/filters/HiddenFilter.cpp
    service/filters/NameFilter.cpp
    service/filters/SizeFilter.cpp
    service/filters/TypeFilter.cpp
)

target_include_directories(domain_layer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})