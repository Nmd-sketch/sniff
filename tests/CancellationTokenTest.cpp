#include <gtest/gtest.h>

#include "../src/domain/model/CancellationToken.hpp"

TEST(CancellationToken, StartsNotStopped) {
    domain::CancellationToken token;
    EXPECT_FALSE(token.isStopped());
}

TEST(CancellationToken, RequestStopFlipsFlag) {
    domain::CancellationToken token;
    token.requestStop();
    EXPECT_TRUE(token.isStopped());
}

TEST(CancellationToken, RequestStopIsIdempotent) {
    domain::CancellationToken token;
    token.requestStop();
    token.requestStop();
    EXPECT_TRUE(token.isStopped());
}