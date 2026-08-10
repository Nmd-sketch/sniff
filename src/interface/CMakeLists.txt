add_library(interface_layer STATIC
    cli/CliController.cpp
    cli/CommandParser.cpp

    formatter/Formatting.cpp
    formatter/JsonFormatter.cpp
    formatter/TableFormatter.cpp
    formatter/TreeFormatter.cpp
)

target_include_directories(interface_layer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(interface_layer PRIVATE application_layer)