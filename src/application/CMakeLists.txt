add_library(application_layer STATIC
    dto/Config.hpp
    dto/QueryResult.hpp
    dto/ScanConfig.hpp

    port/ICommandHandler.hpp

    service/CommandExecutor.cpp
    service/CommandHandler.cpp
    service/CommandQueue.hpp
)

target_include_directories(application_layer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})