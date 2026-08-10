#include <gtest/gtest.h>

#include "../src/domain/model/CaseMode.hpp"
#include "../src/domain/model/MatchMode.hpp"
#include "../src/domain/service/Matcher.hpp"

TEST(Matcher, FixedMatchesSubstring) {
    const domain::Matcher matcher("main", MatchMode::FIXED, CaseMode::SENSITIVE);
    EXPECT_TRUE(matcher.matches("main.cpp"));
    EXPECT_TRUE(matcher.matches("src/main.cpp"));
    EXPECT_FALSE(matcher.matches("README.md"));
}

TEST(Matcher, FixedIsSensitiveByDefault) {
    const domain::Matcher matcher("Main", MatchMode::FIXED, CaseMode::SENSITIVE);
    EXPECT_FALSE(matcher.matches("main.cpp"));
}

TEST(Matcher, FixedIgnoreCase) {
    const domain::Matcher matcher("MAIN", MatchMode::FIXED, CaseMode::INSENSITIVE);
    EXPECT_TRUE(matcher.matches("src/main.cpp"));
}

TEST(Matcher, GlobAsteriskMatchesAny) {
    const domain::Matcher matcher("*.cpp", MatchMode::GLOB, CaseMode::SENSITIVE);
    EXPECT_TRUE(matcher.matches("main.cpp"));
    EXPECT_TRUE(matcher.matches("deep/path/util.cpp"));
    EXPECT_FALSE(matcher.matches("main.h"));
    EXPECT_FALSE(matcher.matches("main.cpp.bak"));
}

TEST(Matcher, GlobQuestionMarkMatchesSingleChar) {
    const domain::Matcher matcher("?at", MatchMode::GLOB, CaseMode::SENSITIVE);
    EXPECT_TRUE(matcher.matches("cat"));
    EXPECT_FALSE(matcher.matches("chat"));
    EXPECT_FALSE(matcher.matches("cat.png"));
}

TEST(Matcher, GlobCharacterClass) {
    const domain::Matcher matcher("file[0-9].txt", MatchMode::GLOB, CaseMode::SENSITIVE);
    EXPECT_TRUE(matcher.matches("file7.txt"));
    EXPECT_FALSE(matcher.matches("filex.txt"));
}

TEST(Matcher, GlobIgnoreCase) {
    const domain::Matcher matcher("*.CPP", MatchMode::GLOB, CaseMode::INSENSITIVE);
    EXPECT_TRUE(matcher.matches("main.cpp"));
}

TEST(Matcher, RegexSearchIsUnanchored) {
    const domain::Matcher matcher("[0-9]+", MatchMode::REGEX, CaseMode::SENSITIVE);
    EXPECT_TRUE(matcher.matches("file123.txt"));
    EXPECT_FALSE(matcher.matches("readme.md"));
}

TEST(Matcher, RegexIgnoreCase) {
    const domain::Matcher matcher("^readme", MatchMode::REGEX, CaseMode::INSENSITIVE);
    EXPECT_TRUE(matcher.matches("README.md"));
}

TEST(Matcher, InvalidPatternThrows) {
    EXPECT_THROW(domain::Matcher("[unclosed", MatchMode::REGEX, CaseMode::SENSITIVE),
                 std::invalid_argument);
}