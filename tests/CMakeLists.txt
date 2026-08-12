include(FetchContent)

set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
)

FetchContent_MakeAvailable(googletest)

add_executable(sniff_tests
    SmokeTest.cpp
    ParserTest.cpp
    EntryModelTest.cpp
    FormatterTest.cpp
    CancellationTokenTest.cpp
    CliControllerTest.cpp
    MatcherTest.cpp
    FilterTest.cpp
    FilterFactoryTest.cpp
    SorterTest.cpp
    SearchServiceTest.cpp
)

if(WIN32)
    target_sources(sniff_tests PRIVATE
        ScannerCoreTest.cpp
        Win32ScannerTest.cpp
        CliControllerEndToEndTest.cpp
    )
endif()

target_link_libraries(sniff_tests PRIVATE
    GTest::gtest_main
    interface_layer
    application_layer
    infrastructure_layer
)

include(GoogleTest)
gtest_discover_tests(sniff_tests)