#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <guardian/glob.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using guardian::globError;
using guardian::globMatch;

TEST(Glob, StarStaysInsideSegment) {
  EXPECT_TRUE(globMatch("/a/*.txt", "/a/x.txt"));
  EXPECT_TRUE(globMatch("/a/*.txt", "/a/.txt"));
  EXPECT_FALSE(globMatch("/a/*.txt", "/a/b/x.txt"));
  EXPECT_FALSE(globMatch("/a/*.txt", "/a/x.txtt"));
}

TEST(Glob, DoubleStarMatchesAnyDepth) {
  EXPECT_TRUE(globMatch("**/.env", "/.env"));
  EXPECT_TRUE(globMatch("**/.env", "/Users/a/proj/.env"));
  EXPECT_FALSE(globMatch("**/.env", "/a/.env.local"));
  EXPECT_FALSE(globMatch("**/.env", "/a/x.env"));
  EXPECT_FALSE(globMatch("**/.env", "/a/.env/x"));
  EXPECT_TRUE(globMatch("**/.env.*", "/a/.env.local"));
  EXPECT_FALSE(globMatch("**/.env.*", "/a/.env"));
}

TEST(Glob, TrailingDoubleStarIncludesDirectoryItself) {
  const std::string_view p = "/Users/*/.ssh/**";
  EXPECT_TRUE(globMatch(p, "/Users/bob/.ssh"));
  EXPECT_TRUE(globMatch(p, "/Users/bob/.ssh/id_rsa"));
  EXPECT_TRUE(globMatch(p, "/Users/bob/.ssh/k/x/id"));
  EXPECT_FALSE(globMatch(p, "/Users/bob/x/.ssh/id"));
  EXPECT_FALSE(globMatch(p, "/Users/bob/alice/.ssh/id"));
  EXPECT_FALSE(globMatch(p, "/Users/.ssh/id"));
}

TEST(Glob, MiddleDoubleStar) {
  EXPECT_TRUE(globMatch("/a/**/b", "/a/b"));
  EXPECT_TRUE(globMatch("/a/**/b", "/a/x/y/b"));
  EXPECT_FALSE(globMatch("/a/**/b", "/a/x/c"));
  EXPECT_TRUE(globMatch("**", "/"));
  EXPECT_TRUE(globMatch("**", "/a/b"));
  EXPECT_TRUE(globMatch("**", ""));
}

TEST(Glob, RootAnchoring) {
  EXPECT_FALSE(globMatch("/a/b", "a/b"));
  EXPECT_FALSE(globMatch("/a/b", "/x/a/b"));
  EXPECT_TRUE(globMatch("/a/b", "/a/b"));
}

TEST(Glob, MatchingIsCaseSensitive) { EXPECT_FALSE(globMatch("**/.env", "/a/.ENV")); }

TEST(Glob, ExtraSanity) {
  EXPECT_FALSE(globMatch("/a/**", "/ab"));
  EXPECT_TRUE(globMatch("/a/**", "/a"));
  EXPECT_TRUE(globMatch("/", "/"));
  EXPECT_FALSE(globMatch("/", "/a"));
  EXPECT_TRUE(globMatch("/a/**/**/b", "/a/b"));
  EXPECT_TRUE(globMatch("/a/**/**/b", "/a/x/y/b"));
  EXPECT_FALSE(globMatch("/a/**/**/b", "/a/x/y"));
  EXPECT_FALSE(globMatch("/a", "/a/"));
  EXPECT_TRUE(globMatch("/a/**", "/a/"));
  EXPECT_TRUE(globMatch("/a*b*c", "/aXbYbZc"));
  EXPECT_FALSE(globMatch("/a*b*c", "/aXbYbZ"));
  EXPECT_FALSE(globMatch("/*", "/"));
}

TEST(Glob, PathologicalGlobIsLinearEnough) {
  std::string path;
  for (int i = 0; i < 20000; ++i) {
    path += "/a";
  }
  EXPECT_FALSE(globMatch("**/a/**/a/**/a/**/a/**/b", path));
}

// Reference matcher: plain recursion over segment vectors.
std::vector<std::string> split(std::string_view s) {
  std::vector<std::string> out;
  if (s.empty()) {
    return out;
  }
  std::size_t pos = 0;
  while (true) {
    const std::size_t end = s.find('/', pos);
    if (end == std::string_view::npos) {
      out.emplace_back(s.substr(pos));
      return out;
    }
    out.emplace_back(s.substr(pos, end - pos));
    pos = end + 1;
  }
}

bool refSeg(std::string_view p, std::string_view s) {
  if (p.empty()) {
    return s.empty();
  }
  if (p[0] == '*') {
    for (std::size_t k = 0; k <= s.size(); ++k) {
      if (refSeg(p.substr(1), s.substr(k))) {
        return true;
      }
    }
    return false;
  }
  return !s.empty() && s[0] == p[0] && refSeg(p.substr(1), s.substr(1));
}

bool refSegs(const std::vector<std::string>& p, std::size_t i, const std::vector<std::string>& s,
             std::size_t j) {
  if (i == p.size()) {
    return j == s.size();
  }
  if (p[i] == "**") {
    for (std::size_t k = j; k <= s.size(); ++k) {
      if (refSegs(p, i + 1, s, k)) {
        return true;
      }
    }
    return false;
  }
  return j < s.size() && refSeg(p[i], s[j]) && refSegs(p, i + 1, s, j + 1);
}

void build(const std::vector<std::string>& alphabet, std::size_t maxLen, std::string& cur,
           std::size_t count, std::vector<std::string>& out) {
  out.push_back(cur);
  if (count == maxLen) {
    return;
  }
  for (const auto& a : alphabet) {
    const std::size_t keep = cur.size();
    cur += '/';
    cur += a;
    build(alphabet, maxLen, cur, count + 1, out);
    cur.resize(keep);
  }
}

TEST(Glob, AgreesWithReferenceMatcher) {
  std::vector<std::string> patterns;
  std::vector<std::string> paths;
  std::string cur;
  build({"a", "*", "**", "a*"}, 4, cur, 0, patterns);
  cur.clear();
  build({"a", "b", "ab", "."}, 5, cur, 0, paths);
  for (const auto& pat : patterns) {
    for (const auto& path : paths) {
      // A rooted pattern (all but "") needs a rooted path (all but "").
      const bool rootMismatch = !pat.empty() && path.empty();
      const bool expected =
          !rootMismatch &&
          refSegs(split(std::string_view(pat).substr(std::min<std::size_t>(1, pat.size()))), 0,
                  split(std::string_view(path).substr(std::min<std::size_t>(1, path.size()))), 0);
      ASSERT_EQ(globMatch(pat, path), expected) << "pattern=" << pat << " path=" << path;
    }
  }
}

TEST(Glob, GlobError) {
  for (const char* ok : {"**/.env", "~/.ssh/**", "/etc/*", "~"}) {
    EXPECT_EQ(globError(ok), std::nullopt) << ok;
  }
  const std::vector<std::pair<std::string_view, std::string_view>> bad = {
      {"", "empty target"},
      {"relative/x", "target must start with '/', '~' or '**'"},
      {"~bob/x", "'~' must be followed by '/' or end"},
      {"/a//b", "empty path segment"},
      {"/a/./b", "'.' and '..' segments are not allowed"},
      {"/a/../b", "'.' and '..' segments are not allowed"},
      {"**x/y", "'**' must be a whole segment"},
      {"/a/b**", "'**' must be a whole segment"},
      {"/a/", "trailing '/'"},
  };
  for (const auto& [target, message] : bad) {
    EXPECT_EQ(globError(target), std::optional<std::string>(std::string(message))) << target;
  }
}

}  // namespace
