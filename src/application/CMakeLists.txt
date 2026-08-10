if(WIN32)
    set(PLATFORM_SIGNAL_HANDLER service/SignalHandlerWin.cpp)
else()
    set(PLATFORM_SIGNAL_HANDLER service/SignalHandlerPosix.cpp)
endif()

add_library(application_layer STATIC
    dto/Config.hpp
    dto/QueryResult.hpp
    dto/ScanConfig.hpp

    port/ISearchService.hpp

    service/SearchService.cpp
    service/SignalHandler.hpp
    ${PLATFORM_SIGNAL_HANDLER}
)

target_include_directories(application_layer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(application_layer PUBLIC domain_layer)