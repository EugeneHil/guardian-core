#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <guardian/path.hpp>

namespace {

using Case = std::pair<std::string_view, std::string_view>;

TEST(NormalizePath, Table) {
  const std::vector<Case> cases = {
      {"/Users/a//proj/./x", "/Users/a/proj/x"},
      {"/Users/a/proj/../.ssh/id_rsa", "/Users/a/.ssh/id_rsa"},
      {"/../../etc/hosts", "/private/etc/hosts"},
      {"/tmp", "/private/tmp"},
      {"/tmp/x/", "/private/tmp/x"},
      {"/var/folders/a", "/private/var/folders/a"},
      {"/etc", "/private/etc"},
      {"/tmpfoo", "/tmpfoo"},
      {"/private/tmp/x", "/private/tmp/x"},
      {"/variable", "/variable"},
      {"/", "/"},
      {"//", "/"},
      {"/..", "/"},
      {"", ""},
      {"a/../b", "b"},
      {"./a", "a"},
      {"../a", "../a"},
      {"a/../../b", "../b"},
      {"a/", "a"},
      {".", ""},
      {"/tmp/../etc", "/private/etc"},
  };
  for (const auto& [in, want] : cases) {
    EXPECT_EQ(guardian::normalizePath(in), want) << "input: " << in;
  }
}

TEST(NormalizePath, EmbeddedNulIsOrdinaryByte) {
  const std::string in("/a/\0b/../c", 10);
  EXPECT_EQ(guardian::normalizePath(in), "/a/c");
  const std::string nul("/a/\0b//c", 8);
  EXPECT_EQ(guardian::normalizePath(nul), std::string("/a/\0b/c", 7));
}

TEST(NormalizePath, VeryLongPathIsIterative) {
  std::string in;
  while (in.size() < (1U << 20U)) {
    in += "/ab";
  }
  EXPECT_EQ(guardian::normalizePath(in), in);
  std::string dots;
  while (dots.size() < (1U << 20U)) {
    dots += "/a/..";
  }
  EXPECT_EQ(guardian::normalizePath(dots), "/");
}

TEST(IsCanonicalPath, True) {
  EXPECT_TRUE(guardian::isCanonicalPath("/Users/a/.env"));
  EXPECT_TRUE(guardian::isCanonicalPath("/"));
  EXPECT_TRUE(guardian::isCanonicalPath("/tmpfoo"));
  EXPECT_TRUE(guardian::isCanonicalPath("/private/tmp/x"));
}

TEST(IsCanonicalPath, False) {
  for (std::string_view p : {"", "a/b", "/a//b", "/a/./b", "/a/../b", "/a/", "/tmp/x", "/var",
                             "/etc/hosts", "/tmp", "/a/.", "/a/.."}) {
    EXPECT_FALSE(guardian::isCanonicalPath(p)) << "input: " << p;
  }
}

TEST(IsCanonicalPath, NulIsOrdinaryByte) {
  EXPECT_TRUE(guardian::isCanonicalPath(std::string_view("/a/\0b", 5)));
}

TEST(ExpandTarget, Table) {
  const std::vector<Case> cases = {
      {"~", "/Users/*"},      {"~/.ssh/**", "/Users/*/.ssh/**"},
      {"**/.env", "**/.env"}, {"/etc/x", "/etc/x"},
      {"~bob/x", "~bob/x"},   {"", ""},
  };
  for (const auto& [in, want] : cases) {
    EXPECT_EQ(guardian::expandTarget(in), want) << "input: " << in;
  }
}

}  // namespace
