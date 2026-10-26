#include "guardian/version.hpp"

#include <gtest/gtest.h>

#include <regex>
#include <string>

TEST(Version, IsSemver) {
  EXPECT_TRUE(
      std::regex_match(std::string(guardian::coreVersion()), std::regex(R"(\d+\.\d+\.\d+)")));
  EXPECT_EQ(guardian::coreVersion(), "0.2.0");
}
