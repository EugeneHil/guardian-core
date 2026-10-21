#include <gtest/gtest.h>

#include <cstddef>
#include <random>
#include <string>
#include <string_view>
#include <vector>
#include <warden/engine.hpp>
#include <warden/policy.hpp>
#include <warden/policy_parser.hpp>

#include "test_support.hpp"

namespace {

using warden::Engine;
using warden::makeRequest;
using warden::makeSpecPolicy;
using warden::parsePolicy;
using warden::Policy;
using warden::ProcessInfo;
using warden::ProcessMatcher;
using warden::Rule;
using warden::Verdict;

ProcessInfo chrome() {
  ProcessInfo info;
  info.path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  info.signingId = "com.google.Chrome";
  info.teamId = "EQHXZ8M8AV";
  return info;
}

Policy singleTargetPolicy(const char* target) {
  Policy policy;
  policy.version = 1;
  Rule rule;
  rule.id = "r";
  rule.targets = {target};
  ProcessMatcher matcher;
  matcher.signingIdPrefix = "com.google.Chrome";
  rule.processes.push_back(matcher);
  policy.rules.push_back(std::move(rule));
  return policy;
}

TEST(Robustness, DeepNestingDoesNotCrash) {
  const auto arrays = parsePolicy(std::string(100000, '['));
  EXPECT_FALSE(arrays.ok());
  EXPECT_FALSE(arrays.errors.empty());

  std::string objects;
  for (int i = 0; i < 50000; ++i) {
    objects += "{\"rules\":";
  }
  const auto result = parsePolicy(objects);
  EXPECT_FALSE(result.ok());
  EXPECT_FALSE(result.errors.empty());
}

TEST(Robustness, InvalidUtf8IsAnError) {
  const std::string json =
      "{\"schemaVersion\":1,\"version\":1,\"rules\":[{\"id\":\"a\xff\","
      "\"description\":\"d\",\"targets\":[\"**/.env\"],\"action\":\"deny\","
      "\"processes\":[{\"teamId\":\"T\"}]}]}";
  const auto result = parsePolicy(json);
  EXPECT_FALSE(result.ok());
  EXPECT_FALSE(result.errors.empty());
}

TEST(Robustness, LongPathAndNulAreSafe) {
  const Engine engine(makeSpecPolicy());
  const std::string longPath = std::string(1U << 20U, 'a').insert(0, "/") + "/.env";
  const auto decision = engine.evaluate(makeRequest(longPath, chrome()));
  EXPECT_EQ(decision.verdict, Verdict::Deny);
  EXPECT_TRUE(engine.isPotentiallyProtected(longPath));

  const std::string withNul("/Users/bob/\0/.env", 17);
  const std::string_view view(withNul);
  EXPECT_EQ(view.size(), 17U);
  (void)engine.isPotentiallyProtected(view);
  (void)engine.evaluate(makeRequest(withNul, chrome()));
}

TEST(Robustness, PrefilterIsSoundOverCorpus) {
  const std::vector<std::string> corpus = {
      "",
      "/",
      "//",
      "/.env",
      "/.env.local",
      "/Users/bob/.env",
      "/Users/bob/proj/.env",
      "/Users/bob/proj/.env.production",
      "/Users/bob/proj/../.env",
      "/Users/bob/proj/./.env",
      "/Users/bob//proj///.env",
      "/Users/bob/proj/sub/../../.env",
      "/Users/bob/.ssh/id_rsa",
      "/Users/bob/.ssh/",
      "/Users/bob/.ssh",
      "/Users/bob/.ssh/keys/deep/id_ed25519",
      "/Users/bob/./.ssh/id_rsa",
      "/Users/bob/x/../.ssh/id_rsa",
      "/Users/bob/.sshx/id_rsa",
      "/Users/bob/.ssh2/id_rsa",
      "/Users/.ssh/id_rsa",
      "/Users/bob/Documents/notes.txt",
      "/Users/bob/.zshrc",
      "/Users/bob/.gitconfig",
      "/Users/bob/.env/inner",
      "/Users/bob/.envrc",
      "/Users/bob/.environment",
      "/private/tmp/secrets/key",
      "/tmp/secrets/key",
      "/tmp/secrets/a/b/c",
      "/tmp/secrets",
      "/tmp/secrets/",
      "/tmp//secrets//key",
      "/tmp/x/../secrets/key",
      "/private/tmp/x/../secrets/key",
      "/tmp/other/key",
      "/var/tmp/secrets/key",
      "/etc/hosts",
      "/var/root/.ssh/id_rsa",
      "/private/var/root/.ssh/id_rsa",
      "/var/folders/xx/T/.env",
      "/private/var/folders/xx/T/.env",
      "/Applications/Foo.app/.env",
      "relative/.env",
      "./.env",
      "../.env",
      ".env",
      "/a/b/c/d/e/f/g/.env",
      "/Users/bob/.ssh/../.env",
      "/Users/bob/..",
      "/..",
      "/../../.env",
  };

  std::vector<Policy> policies;
  policies.push_back(makeSpecPolicy());
  policies.push_back(singleTargetPolicy("/tmp/secrets/**"));
  policies.push_back(singleTargetPolicy("**"));

  ProcessInfo process = chrome();
  ASSERT_GE(corpus.size(), 40U);
  int denies = 0;
  for (const Policy& policy : policies) {
    const Engine engine(policy);
    for (const std::string& path : corpus) {
      const auto decision = engine.evaluate(makeRequest(path, process));
      if (decision.verdict == Verdict::Deny) {
        ++denies;
        EXPECT_TRUE(engine.isPotentiallyProtected(path)) << "path: '" << path << "'";
      }
    }
  }
  EXPECT_GT(denies, 20) << "corpus must exercise the Deny branch";
}

TEST(Robustness, RandomisedGarbageNeverThrows) {
  std::mt19937 rng(0xC0FFEEU);
  const std::vector<std::string> fragments = {
      "{",       "}",         "[",      "]",    "\"",   ",", ":",  "rules", "\"rules\"", "id",
      "targets", "processes", "teamId", "null", "true", "1", "\\", "\xff",  " "};
  for (int i = 0; i < 2000; ++i) {
    const std::size_t length = rng() % 201U;
    std::string input;
    while (input.size() < length) {
      if (rng() % 3U == 0U) {
        input += fragments[rng() % fragments.size()];
      } else {
        input.push_back(static_cast<char>(rng() % 256U));
      }
    }
    input.resize(length);
    warden::ParseResult result;
    ASSERT_NO_THROW(result = parsePolicy(input)) << "iteration " << i;
    if (result.ok()) {
      EXPECT_TRUE(result.errors.empty());
    }
  }
}

}  // namespace
