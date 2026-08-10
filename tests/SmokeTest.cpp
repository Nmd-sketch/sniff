#include <gtest/gtest.h>

#include "../src/domain/model/FilterSpec.hpp"

TEST(FilterSpec, DefaultConstructedHasNoFilters) {
    FilterSpec spec;

    EXPECT_FALSE(spec.extension.has_value());
    EXPECT_FALSE(spec.min_size.has_value());
    EXPECT_FALSE(spec.max_size.has_value());
    EXPECT_FALSE(spec.detect_hidden.has_value());
    EXPECT_FALSE(spec.modified_within.has_value());
    EXPECT_FALSE(spec.modified_before.has_value());
    EXPECT_FALSE(spec.created_within.has_value());
    EXPECT_FALSE(spec.created_before.has_value());
    EXPECT_FALSE(spec.match_mode.has_value());
    EXPECT_FALSE(spec.case_mode.has_value());
    EXPECT_FALSE(spec.full_path.has_value());
    EXPECT_FALSE(spec.types.has_value());
    EXPECT_FALSE(spec.min_depth.has_value());
    EXPECT_FALSE(spec.max_depth.has_value());
    EXPECT_FALSE(spec.exclude.has_value());
    EXPECT_FALSE(spec.follow_symlinks.has_value());
}

TEST(Smoke, Addition) {
    EXPECT_EQ(2 + 2, 4);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}