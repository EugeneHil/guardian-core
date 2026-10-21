#include <gtest/gtest.h>

#include <regex>
#include <string>

#include "warden/version.hpp"

TEST(Version, IsSemver) {
    EXPECT_TRUE(std::regex_match(std::string(warden::coreVersion()), std::regex(R"(\d+\.\d+\.\d+)")));
    EXPECT_EQ(warden::coreVersion(), "0.1.0");
}
