#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../src/interface/cli/CommandParser.hpp"

namespace {

std::vector<std::string> toArgs(std::initializer_list<const char*> args) {
    return std::vector<std::string>(args.begin(), args.end());
}

CommandParser parseOk(std::initializer_list<const char*> args) {
    CommandParser parser;
    const bool ok = parser.parse(toArgs(args));
    EXPECT_TRUE(ok) << "unexpected parse failure: " << parser.lastError();
    return parser;
}

FilterSpec specOf(const CommandParser& parser) {
    return parser.getFilterSpecs().at(0);
}

}  // namespace

/* ------------------------- positionals ------------------------- */

TEST(ParserPositionals, NoArgsIsValid) {
    const CommandParser parser = parseOk({});

    EXPECT_EQ(parser.getCommands().size(), 0u);
    EXPECT_EQ(parser.getFormatType(), FormatType::TABLE);
    EXPECT_FALSE(specOf(parser).detect_hidden.has_value());
}

TEST(ParserPositionals, SinglePattern) {
    const CommandParser parser = parseOk({"main.cpp"});

    ASSERT_EQ(parser.getCommands().size(), 1u);
    EXPECT_EQ(parser.getCommands()[0], "main.cpp");
}

TEST(ParserPositionals, PatternThenPaths) {
    const CommandParser parser = parseOk({"foo", "a", "b"});

    ASSERT_EQ(parser.getCommands().size(), 3u);
    EXPECT_EQ(parser.getCommands()[0], "foo");
    EXPECT_EQ(parser.getCommands()[1], "a");
    EXPECT_EQ(parser.getCommands()[2], "b");
}

TEST(ParserPositionals, PatternStartingWithDashViaDoubleDash) {
    const CommandParser parser = parseOk({"--", "-pattern"});

    ASSERT_EQ(parser.getCommands().size(), 1u);
    EXPECT_EQ(parser.getCommands()[0], "-pattern");
}

TEST(ParserPositionals, DoubleDashEndsOptionParsing) {
    const CommandParser parser = parseOk({"-e", "py", "--", "-x"});

    ASSERT_EQ(parser.getCommands().size(), 1u);
    EXPECT_EQ(parser.getCommands()[0], "-x");
    EXPECT_EQ(specOf(parser).extension->at(0), "py");
}

TEST(ParserPositionals, LoneDashIsPositional) {
    const CommandParser parser = parseOk({"-"});

    ASSERT_EQ(parser.getCommands().size(), 1u);
    EXPECT_EQ(parser.getCommands()[0], "-");
}

TEST(ParserPositionals, OptionsCanBeInterspersed) {
    const CommandParser parser = parseOk({"-e", "py", "main.py", "-H", "src"});

    ASSERT_EQ(parser.getCommands().size(), 2u);
    EXPECT_EQ(parser.getCommands()[0], "main.py");
    EXPECT_EQ(parser.getCommands()[1], "src");
    EXPECT_TRUE(specOf(parser).detect_hidden.value());
    EXPECT_EQ(specOf(parser).extension->at(0), "py");
}

/* ------------------------- boolean flags ------------------------- */

TEST(ParserFlags, HiddenShortAndLong) {
    EXPECT_TRUE(specOf(parseOk({"-H"})).detect_hidden.value());
    EXPECT_TRUE(specOf(parseOk({"--hidden"})).detect_hidden.value());
}

TEST(ParserFlags, FollowShortAndLong) {
    EXPECT_TRUE(specOf(parseOk({"-L"})).follow_symlinks.value());
    EXPECT_TRUE(specOf(parseOk({"--follow"})).follow_symlinks.value());
}

TEST(ParserFlags, FullPathShortAndLong) {
    EXPECT_TRUE(specOf(parseOk({"-p"})).full_path.value());
    EXPECT_TRUE(specOf(parseOk({"--full-path"})).full_path.value());
}

TEST(ParserFlags, CombinedValuelessShorts) {
    const FilterSpec& spec = specOf(parseOk({"-HLp"}));

    EXPECT_TRUE(spec.detect_hidden.value());
    EXPECT_TRUE(spec.follow_symlinks.value());
    EXPECT_TRUE(spec.full_path.value());
}

TEST(ParserFlags, FlagRejectsInlineValue) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--hidden=1"})));
    EXPECT_EQ(parser.lastError(), "option '--hidden' does not take a value");
}

/* ------------------------- matching options ------------------------- */

TEST(ParserMatching, GlobShortAndLong) {
    EXPECT_EQ(specOf(parseOk({"-g"})).match_mode.value(), MatchMode::GLOB);
    EXPECT_EQ(specOf(parseOk({"--glob"})).match_mode.value(), MatchMode::GLOB);
}

TEST(ParserMatching, FixedStringsShortAndLong) {
    EXPECT_EQ(specOf(parseOk({"-F"})).match_mode.value(), MatchMode::FIXED);
    EXPECT_EQ(specOf(parseOk({"--fixed-strings"})).match_mode.value(), MatchMode::FIXED);
}

TEST(ParserMatching, ConflictingMatchModesRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-g", "-F"})));
    EXPECT_EQ(parser.lastError(), "conflicting matching options (--glob vs --fixed-strings)");
}

TEST(ParserMatching, SameMatchModeRepeatedIsFine) {
    EXPECT_EQ(specOf(parseOk({"-g", "--glob"})).match_mode.value(), MatchMode::GLOB);
}

TEST(ParserMatching, CaseSensitivityFlags) {
    EXPECT_EQ(specOf(parseOk({"-i"})).case_mode.value(), CaseMode::INSENSITIVE);
    EXPECT_EQ(specOf(parseOk({"-s"})).case_mode.value(), CaseMode::SENSITIVE);
    EXPECT_EQ(specOf(parseOk({"--ignore-case"})).case_mode.value(), CaseMode::INSENSITIVE);
    EXPECT_EQ(specOf(parseOk({"--case-sensitive"})).case_mode.value(), CaseMode::SENSITIVE);
}

TEST(ParserMatching, ConflictingCaseFlagsRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-s", "-i"})));
    EXPECT_EQ(parser.lastError(), "conflicting case options (--ignore-case vs --case-sensitive)");
}

TEST(ParserMatching, ConflictingCaseLongFlagsRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--case-sensitive", "--ignore-case"})));
}

/* ------------------------- extension ------------------------- */

TEST(ParserExtension, MultipleExtensions) {
    const FilterSpec& spec = specOf(parseOk({"-e", "py", "-e", "rs"}));

    ASSERT_EQ(spec.extension->size(), 2u);
    EXPECT_EQ(spec.extension->at(0), "py");
    EXPECT_EQ(spec.extension->at(1), "rs");
}

TEST(ParserExtension, LeadingDotIsStripped) {
    const FilterSpec& spec = specOf(parseOk({"-e", ".md"}));

    ASSERT_EQ(spec.extension->size(), 1u);
    EXPECT_EQ(spec.extension->at(0), "md");
}

TEST(ParserExtension, LongFormWithEquals) {
    EXPECT_EQ(specOf(parseOk({"--extension=cpp"})).extension->at(0), "cpp");
}

TEST(ParserExtension, LongFormSeparateValue) {
    EXPECT_EQ(specOf(parseOk({"--extension", "hpp"})).extension->at(0), "hpp");
}

/* ------------------------- types ------------------------- */

TEST(ParserType, CombinedShortShorts) {
    const FilterSpec& spec = specOf(parseOk({"-tf", "-tl"}));

    ASSERT_EQ(spec.types->size(), 2u);
    EXPECT_EQ(spec.types->at(0), FileType::FILE);
    EXPECT_EQ(spec.types->at(1), FileType::SYMLINK);
}

TEST(ParserType, ShortWithSeparateValue) {
    EXPECT_EQ(specOf(parseOk({"-t", "d"})).types->at(0), FileType::DIRECTORY);
}

TEST(ParserType, LongNames) {
    const FilterSpec& spec =
        specOf(parseOk({"--type", "file", "--type", "directory", "--type", "symlink",
                        "--type", "executable", "--type", "empty"}));

    ASSERT_EQ(spec.types->size(), 5u);
    EXPECT_EQ(spec.types->at(0), FileType::FILE);
    EXPECT_EQ(spec.types->at(1), FileType::DIRECTORY);
    EXPECT_EQ(spec.types->at(2), FileType::SYMLINK);
    EXPECT_EQ(spec.types->at(3), FileType::EXECUTABLE);
    EXPECT_EQ(spec.types->at(4), FileType::EMPTY);
}

TEST(ParserType, LongFormWithEquals) {
    EXPECT_EQ(specOf(parseOk({"--type=dir"})).types->at(0), FileType::DIRECTORY);
}

TEST(ParserType, InvalidTypeRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-t", "z"})));
    EXPECT_EQ(parser.lastError(), "invalid type 'z' (expected f, d, l, x or e)");
}

TEST(ParserType, MissingValueRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-t"})));
    EXPECT_EQ(parser.lastError(), "option '-t' requires a value");
}

/* ------------------------- exclude ------------------------- */

TEST(ParserExclude, MultipleExcludes) {
    const FilterSpec& spec = specOf(parseOk({"-E", "*.pyc", "-E", "node_modules"}));

    ASSERT_EQ(spec.exclude->size(), 2u);
    EXPECT_EQ(spec.exclude->at(0), "*.pyc");
    EXPECT_EQ(spec.exclude->at(1), "node_modules");
}

/* ------------------------- size ------------------------- */

TEST(ParserSize, PlusSetsMinSize) {
    const FilterSpec& spec = specOf(parseOk({"-S", "+10M"}));

    EXPECT_EQ(spec.min_size.value(), static_cast<std::uintmax_t>(10000000));
    EXPECT_FALSE(spec.max_size.has_value());
}

TEST(ParserSize, MinusSetsMaxSize) {
    const FilterSpec& spec = specOf(parseOk({"--size", "-1G"}));

    EXPECT_EQ(spec.max_size.value(), static_cast<std::uintmax_t>(1000000000));
    EXPECT_FALSE(spec.min_size.has_value());
}

TEST(ParserSize, ValueWithLeadingDashIsConsumed) {
    const FilterSpec& spec = specOf(parseOk({"-S", "-1G"}));

    EXPECT_EQ(spec.max_size.value(), static_cast<std::uintmax_t>(1000000000));
}

TEST(ParserSize, BinaryUnits) {
    const FilterSpec& ki = specOf(parseOk({"--size=+2Ki"}));
    EXPECT_EQ(ki.min_size.value(), static_cast<std::uintmax_t>(2048));

    const FilterSpec& mi = specOf(parseOk({"-S", "+2Mi"}));
    EXPECT_EQ(mi.min_size.value(), static_cast<std::uintmax_t>(2097152));
}

TEST(ParserSize, ExactSizeSetsBothBounds) {
    const FilterSpec& spec = specOf(parseOk({"--size", "42b"}));

    EXPECT_EQ(spec.min_size.value(), static_cast<std::uintmax_t>(42));
    EXPECT_EQ(spec.max_size.value(), static_cast<std::uintmax_t>(42));
}

TEST(ParserSize, DecimalValue) {
    EXPECT_EQ(specOf(parseOk({"--size", "+1.5M"})).min_size.value(),
              static_cast<std::uintmax_t>(1500000));
}

TEST(ParserSize, UnitIsCaseInsensitive) {
    const FilterSpec& spec = specOf(parseOk({"-S", "+10g"}));

    EXPECT_EQ(spec.min_size.value(), static_cast<std::uintmax_t>(10000000000));
}

TEST(ParserSize, NoUnitMeansBytes) {
    EXPECT_EQ(specOf(parseOk({"-S", "+500"})).min_size.value(), static_cast<std::uintmax_t>(500));
}

TEST(ParserSize, MinAndMaxCombined) {
    const FilterSpec& spec = specOf(parseOk({"-S", "+1k", "-S", "-10k"}));

    EXPECT_EQ(spec.min_size.value(), static_cast<std::uintmax_t>(1000));
    EXPECT_EQ(spec.max_size.value(), static_cast<std::uintmax_t>(10000));
}

TEST(ParserSize, ValueAttachedToShort) {
    EXPECT_EQ(specOf(parseOk({"-S+1M"})).min_size.value(), static_cast<std::uintmax_t>(1000000));
}

TEST(ParserSize, TooLargeRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-S", "+999999999999T"})));
}

TEST(ParserSize, UnknownUnitRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-S", "10MB"})));
    EXPECT_EQ(parser.lastError(), "invalid size unit 'mb' in '10MB'");
}

TEST(ParserSize, GarbageRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-S", "abc"})));
    EXPECT_EQ(parser.lastError(), "invalid size 'abc' (expected [+-]NUM[UNIT], e.g. +10M or -1G)");
}

TEST(ParserSize, MissingValueRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-S"})));
    EXPECT_EQ(parser.lastError(), "option '-S' requires a value");
}

TEST(ParserSize, EmptyEqualsValueRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--size="})));
    EXPECT_EQ(parser.lastError(), "option '--size' requires a value");
}

/* ------------------------- depth ------------------------- */

TEST(ParserDepth, MaxDepthShortAndLong) {
    EXPECT_EQ(specOf(parseOk({"-d", "3"})).max_depth.value(), 3);
    EXPECT_EQ(specOf(parseOk({"--max-depth=1"})).max_depth.value(), 1);
}

TEST(ParserDepth, MinDepth) {
    const FilterSpec& spec = specOf(parseOk({"--min-depth", "2"}));

    EXPECT_EQ(spec.min_depth.value(), 2);
    EXPECT_FALSE(spec.max_depth.has_value());
}

TEST(ParserDepth, EqualBoundsAreAllowed) {
    const FilterSpec& spec = specOf(parseOk({"--min-depth", "1", "--max-depth", "1"}));

    EXPECT_EQ(spec.min_depth.value(), 1);
    EXPECT_EQ(spec.max_depth.value(), 1);
}

TEST(ParserDepth, MinGreaterThanMaxRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--min-depth", "3", "-d", "2"})));
    EXPECT_EQ(parser.lastError(), "--min-depth cannot be greater than --max-depth");
}

TEST(ParserDepth, ConflictRejectedRegardlessOfOrder) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-d", "2", "--min-depth", "3"})));
}

TEST(ParserDepth, NonNumericRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-d", "abc"})));
    EXPECT_EQ(parser.lastError(), "invalid depth 'abc' (expected a non-negative integer)");
}

TEST(ParserDepth, NegativeValueRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--max-depth", "-1"})));
    EXPECT_EQ(parser.lastError(), "option '--max-depth' requires a value");
}

TEST(ParserDepth, MissingValueRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-d"})));
    EXPECT_EQ(parser.lastError(), "option '-d' requires a value");
}

/* ------------------------- dates ------------------------- */

TEST(ParserDates, ChangedWithin) {
    const FilterSpec& spec = specOf(parseOk({"--changed-within", "2weeks"}));

    EXPECT_EQ(spec.modified_within.value(), "2weeks");
}

TEST(ParserDates, ChangedBefore) {
    const FilterSpec& spec = specOf(parseOk({"--changed-before", "2018-10-27"}));

    EXPECT_EQ(spec.modified_before.value(), "2018-10-27");
}

TEST(ParserDates, CreatedWithin) {
    const FilterSpec& spec = specOf(parseOk({"--created-within", "1d"}));

    EXPECT_EQ(spec.created_within.value(), "1d");
}

TEST(ParserDates, CreatedBefore) {
    const FilterSpec& spec = specOf(parseOk({"--created-before", "yesterday"}));

    EXPECT_EQ(spec.created_before.value(), "yesterday");
}

TEST(ParserDates, BothBoundsCanBeSet) {
    const FilterSpec& spec =
        specOf(parseOk({"--changed-within", "2weeks", "--changed-before", "1week"}));

    EXPECT_EQ(spec.modified_within.value(), "2weeks");
    EXPECT_EQ(spec.modified_before.value(), "1week");
}

/* ------------------------- format ------------------------- */

TEST(ParserFormat, DefaultIsTable) {
    EXPECT_EQ(parseOk({}).getFormatType(), FormatType::TABLE);
}

TEST(ParserFormat, ExplicitValues) {
    EXPECT_EQ(parseOk({"--format", "json"}).getFormatType(), FormatType::JSON);
    EXPECT_EQ(parseOk({"--format=tree"}).getFormatType(), FormatType::TREE);
    EXPECT_EQ(parseOk({"--format", "table"}).getFormatType(), FormatType::TABLE);
}

TEST(ParserFormat, CaseInsensitive) {
    EXPECT_EQ(parseOk({"--format", "JSON"}).getFormatType(), FormatType::JSON);
}

TEST(ParserFormat, InvalidRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--format", "xml"})));
    EXPECT_EQ(parser.lastError(), "invalid format 'xml' (expected tree, table or json)");
}

TEST(ParserFormat, MissingValueRejected) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--format"})));
    EXPECT_EQ(parser.lastError(), "option '--format' requires a value");
}

/* ------------------------- errors ------------------------- */

TEST(ParserErrors, UnknownLongOption) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--bogus"})));
    EXPECT_EQ(parser.lastError(), "unknown option '--bogus'");
}

TEST(ParserErrors, UnknownShortOption) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-z"})));
    EXPECT_EQ(parser.lastError(), "unknown option '-z'");
}

TEST(ParserErrors, ValueConsumedOnlyIfNotAnOption) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"--exclude", "--hidden"})));
    EXPECT_EQ(parser.lastError(), "option '--exclude' requires a value");
}

TEST(ParserErrors, FailedParseLeavesEmptyState) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"foo", "-z"})));

    EXPECT_TRUE(parser.getFilterSpecs().empty());
    EXPECT_TRUE(parser.getCommands().empty());
    EXPECT_FALSE(parser.lastError().empty());
}

TEST(ParserErrors, FailedParseCanBeRetried) {
    CommandParser parser;
    EXPECT_FALSE(parser.parse(toArgs({"-z"})));
    EXPECT_TRUE(parser.parse(toArgs({"-H", "ok"})));

    EXPECT_TRUE(specOf(parser).detect_hidden.value());
    ASSERT_EQ(parser.getCommands().size(), 1u);
    EXPECT_EQ(parser.getCommands()[0], "ok");
}

/* ------------------------- combined usage ------------------------- */

TEST(ParserCombined, FullCommandLine) {
    const CommandParser parser = parseOk(
        {"-H", "-tf", "-e", "cpp", "-S", "+1k", "-S", "-1M", "--min-depth", "1",
         "--max-depth=4", "--changed-before", "2020-01-01", "-E", "build", "-g", "main",
         "src"});

    const FilterSpec& spec = specOf(parser);

    EXPECT_TRUE(spec.detect_hidden.value());
    ASSERT_EQ(spec.types->size(), 1u);
    EXPECT_EQ(spec.types->at(0), FileType::FILE);
    ASSERT_EQ(spec.extension->size(), 1u);
    EXPECT_EQ(spec.extension->at(0), "cpp");
    EXPECT_EQ(spec.min_size.value(), static_cast<std::uintmax_t>(1000));
    EXPECT_EQ(spec.max_size.value(), static_cast<std::uintmax_t>(1000000));
    EXPECT_EQ(spec.min_depth.value(), 1);
    EXPECT_EQ(spec.max_depth.value(), 4);
    EXPECT_TRUE(spec.modified_before.has_value());
    ASSERT_EQ(spec.exclude->size(), 1u);
    EXPECT_EQ(spec.exclude->at(0), "build");
    EXPECT_EQ(spec.match_mode.value(), MatchMode::GLOB);

    ASSERT_EQ(parser.getCommands().size(), 2u);
    EXPECT_EQ(parser.getCommands()[0], "main");
    EXPECT_EQ(parser.getCommands()[1], "src");
}
