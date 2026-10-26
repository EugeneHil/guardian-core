#include <gtest/gtest.h>

#include <guardian/engine.hpp>
#include <guardian/policy.hpp>
#include <string>

#include "test_support.hpp"

namespace {

using guardian::AccessRequest;
using guardian::Decision;
using guardian::Engine;
using guardian::makeRequest;
using guardian::makeSpecPolicy;
using guardian::Policy;
using guardian::ProcessInfo;
using guardian::ProcessMatcher;
using guardian::Rule;
using guardian::Verdict;

ProcessInfo chrome() {
  ProcessInfo info;
  info.path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  info.signingId = "com.google.Chrome";
  info.teamId = "EQHXZ8M8AV";
  return info;
}

ProcessInfo withSigningId(const char* signingId) {
  ProcessInfo info;
  info.signingId = signingId;
  return info;
}

ProcessMatcher prefixMatcher(const char* prefix) {
  ProcessMatcher matcher;
  matcher.signingIdPrefix = prefix;
  return matcher;
}

Rule makeRule(const char* id, const char* target, const char* prefix) {
  Rule rule;
  rule.id = id;
  rule.targets = {target};
  rule.processes = {prefixMatcher(prefix)};
  return rule;
}

TEST(Engine, DeniesChromeOpeningEnv) {
  const Engine engine(makeSpecPolicy());
  const Decision decision = engine.evaluate(makeRequest("/Users/bob/proj/api/.env", chrome()));
  EXPECT_EQ(decision.verdict, Verdict::Deny);
  EXPECT_EQ(decision.ruleId, "secrets-from-browsers-and-ai");
}

TEST(Engine, AllowsTerminalOpeningEnv) {
  const Engine engine(makeSpecPolicy());
  const Decision decision =
      engine.evaluate(makeRequest("/Users/bob/proj/.env", withSigningId("com.apple.Terminal")));
  EXPECT_EQ(decision.verdict, Verdict::Allow);
  EXPECT_TRUE(decision.ruleId.empty());
}

TEST(Engine, DeniesHelperViaResponsibleProcess) {
  const Engine engine(makeSpecPolicy());
  const Decision decision = engine.evaluate(makeRequest(
      "/Users/bob/.env", withSigningId("com.example.helper"), withSigningId("com.google.Chrome")));
  EXPECT_EQ(decision.verdict, Verdict::Deny);
}

TEST(Engine, AllowsWhenNeitherProcessMatches) {
  const Engine engine(makeSpecPolicy());
  const Decision decision = engine.evaluate(makeRequest(
      "/Users/bob/.env", withSigningId("com.example.helper"), withSigningId("com.example.parent")));
  EXPECT_EQ(decision.verdict, Verdict::Allow);
  EXPECT_TRUE(decision.ruleId.empty());
}

TEST(Engine, DeniesPythonByPathOnSshKey) {
  const Engine engine(makeSpecPolicy());
  ProcessInfo python;
  python.path = "/usr/bin/python3";
  const Decision decision = engine.evaluate(makeRequest("/Users/alice/.ssh/id_ed25519", python));
  EXPECT_EQ(decision.verdict, Verdict::Deny);
}

TEST(Engine, TildeMatchesAnyHomeDirectlyUnderUsers) {
  const Engine engine(makeSpecPolicy());
  EXPECT_EQ(engine.evaluate(makeRequest("/Users/alice/.ssh/id", chrome())).verdict, Verdict::Deny);
  EXPECT_EQ(engine.evaluate(makeRequest("/Users/alice/.sshx/id", chrome())).verdict,
            Verdict::Allow);
  EXPECT_EQ(engine.evaluate(makeRequest("/Users/alice/sub/.ssh/id", chrome())).verdict,
            Verdict::Allow);
}

TEST(Engine, MatcherRequiresAllFields) {
  ProcessMatcher matcher;
  matcher.teamId = "A";
  matcher.signingIdPrefix = "com.x";
  ProcessInfo other;
  other.teamId = "A";
  other.signingId = "com.y.z";
  EXPECT_FALSE(guardian::matchesProcess(matcher, other));
  ProcessInfo same;
  same.teamId = "A";
  same.signingId = "com.x.z";
  EXPECT_TRUE(guardian::matchesProcess(matcher, same));
}

TEST(Engine, EmptyMatcherNeverMatches) {
  EXPECT_FALSE(guardian::matchesProcess(ProcessMatcher{}, chrome()));
  EXPECT_FALSE(guardian::matchesProcess(ProcessMatcher{}, ProcessInfo{}));
}

TEST(Engine, EmptyFieldsNeverMatchUnsignedProcess) {
  ProcessMatcher team;
  team.teamId = "";
  ProcessMatcher prefix;
  prefix.signingIdPrefix = "";
  EXPECT_FALSE(guardian::matchesProcess(team, ProcessInfo{}));
  EXPECT_FALSE(guardian::matchesProcess(prefix, ProcessInfo{}));
  EXPECT_FALSE(guardian::matchesProcess(prefix, chrome()));
}

TEST(Engine, TmpAliasEquivalence) {
  Policy policy;
  policy.rules.push_back(makeRule("tmp", "/tmp/secrets/**", "com.google"));
  const Engine engine(policy);
  EXPECT_EQ(engine.evaluate(makeRequest("/tmp/secrets/a", chrome())).verdict, Verdict::Deny);
  EXPECT_EQ(engine.evaluate(makeRequest("/private/tmp/secrets/a", chrome())).verdict,
            Verdict::Deny);
}

TEST(Engine, DotDotCannotEscape) {
  const Engine engine(makeSpecPolicy());
  EXPECT_EQ(engine.evaluate(makeRequest("/Users/alice/proj/../.ssh/id_rsa", chrome())).verdict,
            Verdict::Deny);
  EXPECT_EQ(engine.evaluate(makeRequest("/Users/alice/.ssh/../proj/x", chrome())).verdict,
            Verdict::Allow);
}

TEST(Engine, FirstMatchingRuleWins) {
  Policy policy;
  policy.rules.push_back(makeRule("r1", "/data/**", "com.google"));
  policy.rules.push_back(makeRule("r2", "/data/**", "com.google"));
  const Engine engine(policy);
  EXPECT_EQ(engine.evaluate(makeRequest("/data/x", chrome())).ruleId, "r1");
}

TEST(Engine, EmptyPolicyAllowsEverything) {
  const Engine engine{Policy{}};
  EXPECT_EQ(engine.evaluate(makeRequest("/Users/a/.env", chrome())).verdict, Verdict::Allow);
  EXPECT_FALSE(engine.isPotentiallyProtected("/Users/a/.env"));
}

TEST(Engine, EmptyPathIsAllowed) {
  const Engine engine(makeSpecPolicy());
  EXPECT_EQ(engine.evaluate(makeRequest("", chrome())).verdict, Verdict::Allow);
}

TEST(Engine, PrefilterCandidates) {
  const Engine engine(makeSpecPolicy());
  EXPECT_TRUE(engine.isPotentiallyProtected("/Users/alice/.ssh/id"));
  EXPECT_TRUE(engine.isPotentiallyProtected("/Users/alice/proj/.env"));
  EXPECT_FALSE(engine.isPotentiallyProtected("/usr/lib/libc.dylib"));
  EXPECT_FALSE(engine.isPotentiallyProtected("/Users/alice/proj/.envrc"));
  EXPECT_TRUE(engine.isPotentiallyProtected("/tmp/x"));
  EXPECT_TRUE(engine.isPotentiallyProtected("/a/../b"));
  EXPECT_TRUE(engine.isPotentiallyProtected(""));
}

TEST(Engine, FreeEvaluateMatchesEngine) {
  const Policy policy = makeSpecPolicy();
  const AccessRequest request = makeRequest("/Users/bob/.env", chrome());
  const Decision viaFree = guardian::evaluate(policy, request);
  const Decision viaEngine = Engine(policy).evaluate(request);
  EXPECT_EQ(viaFree.verdict, viaEngine.verdict);
  EXPECT_EQ(viaFree.ruleId, viaEngine.ruleId);
}

}  // namespace
