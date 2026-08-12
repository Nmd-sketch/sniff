if(WIN32)
    set(SCANNER_SOURCES
        scanner/Win32Scanner.cpp
        scanner/Win32ScanCore.cpp
    )
else()
    set(SCANNER_SOURCES)
endif()

add_library(infrastructure_layer STATIC ${SCANNER_SOURCES})

target_include_directories(infrastructure_layer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(infrastructure_layer PUBLIC domain_layer)