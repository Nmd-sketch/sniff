#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <windows.h>

#include "../src/application/service/SearchService.hpp"
#include "../src/infrastructure/scanner/Win32Scanner.hpp"
#include "cli/CliController.hpp"

namespace {

std::string capture(std::ostream& stream, const std::function<void()>& action) {
    std::ostringstream buffer;
    std::streambuf* previous = stream.rdbuf(buffer.rdbuf());
    action();
    stream.rdbuf(previous);
    return buffer.str();
}

class TempDir {
public:
    TempDir() {
        const auto base = std::filesystem::temp_directory_path();
        for (int attempt = 0; attempt < 10; ++attempt) {
            const auto candidate =
                base / ("sniff_e2e_" + std::to_string(GetCurrentProcessId()) + "_" +
                        std::to_string(m_counter++));
            if (std::filesystem::create_directory(candidate)) {
                m_root = candidate;
                return;
            }
        }
        throw std::runtime_error("unable to create a temporary directory");
    }

    ~TempDir() {
        if (!m_root.empty()) {
            std::error_code error;
            std::filesystem::remove_all(m_root, error);
        }
    }

    std::string root() const {
        std::string value = m_root.string();
        for (char& c : value) {
            if (c == '\\') c = '/';
        }
        return value;
    }

    void makeFile(const std::string& relative, const std::string& content) const {
        std::ofstream out(m_root / relative, std::ios::binary);
        out << content;
    }

    void makeDir(const std::string& relative) const {
        std::filesystem::create_directories(m_root / relative);
    }

private:
    std::filesystem::path m_root;
    static int m_counter;
};

int TempDir::m_counter = 0;

}  // namespace

TEST(CliE2E, SearchesFilesAndPrintsTable) {
    TempDir dir;
    dir.makeDir("src");
    dir.makeFile("src/main.cpp", "int main() {}");
    dir.makeFile("src/util.hpp", "int util();");
    dir.makeFile("tests/x.cpp", "");

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    const std::string out = capture(std::cout, [&] {
        EXPECT_EQ(controller.run({"main.cpp", dir.root()}), 0);
    });

    EXPECT_NE(out.find("main.cpp"), std::string::npos);
    EXPECT_EQ(out.find("util.hpp"), std::string::npos);
    EXPECT_EQ(out.find("x.cpp"), std::string::npos);
}

TEST(CliE2E, ExtensionFilterKeepsOnlyMatchingFiles) {
    TempDir dir;
    dir.makeFile("main.cpp", "int main() {}");
    dir.makeFile("util.hpp", "int util();");
    dir.makeFile("x.cpp", "");

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    const std::string out = capture(std::cout, [&] {
        EXPECT_EQ(controller.run({"*", dir.root(), "--glob", "--extension", "cpp"}), 0);
    });

    EXPECT_NE(out.find("main.cpp"), std::string::npos);
    EXPECT_NE(out.find("x.cpp"), std::string::npos);
    EXPECT_EQ(out.find("util.hpp"), std::string::npos);
}

TEST(CliE2E, MaxDepthLimitsOutput) {
    TempDir dir;
    dir.makeDir("sub");
    dir.makeFile("top.txt", "t");
    dir.makeFile("sub/mid.txt", "m");

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    const std::string out = capture(std::cout, [&] {
        EXPECT_EQ(controller.run({"*", dir.root(), "--glob", "--max-depth", "0"}), 0);
    });

    EXPECT_NE(out.find("top.txt"), std::string::npos);
    EXPECT_EQ(out.find("mid.txt"), std::string::npos);
}

TEST(CliE2E, JsonFormatExposesPaths) {
    TempDir dir;
    dir.makeDir("src");
    dir.makeFile("src/main.cpp", "int main() {}");

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    const std::string out = capture(std::cout, [&] {
        EXPECT_EQ(controller.run({"*", dir.root(), "--glob", "--format", "json"}), 0);
    });

    EXPECT_NE(out.find("\"name\": \"main.cpp\""), std::string::npos);
    EXPECT_NE(out.find("\"path\": \"" + dir.root() + "/src/main.cpp\""), std::string::npos);
}

TEST(CliE2E, NoMatchesProducesEmptyTable) {
    TempDir dir;
    dir.makeFile("main.cpp", "int main() {}");

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    const std::string out = capture(std::cout, [&] {
        EXPECT_EQ(controller.run({"zzz_nothing*", dir.root()}), 0);
    });

    EXPECT_TRUE(out.empty());
}