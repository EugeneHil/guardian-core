#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>
#include <guardian/policy_parser.hpp>

namespace {

using guardian::describe;
using guardian::parsePolicy;
using guardian::ParseResult;

using Messages = std::vector<std::string>;

const char* const kTargets = R"(["**/secret.txt"])";
const char* const kProcesses = R"([{"teamId":"X"}])";

std::string policyJson(const std::string& rulesFragment, const std::string& schemaVersion = "1",
                       const std::string& version = "1") {
  return R"({"schemaVersion":)" + schemaVersion + R"(,"version":)" + version + R"(,"rules":[)" +
         rulesFragment + "]}";
}

std::string ruleJson(const std::string& id, const std::string& targets, const std::string& action,
                     const std::string& processes) {
  return R"({"id":")" + id + R"(","targets":)" + targets + R"(,"action":")" + action +
         R"(","processes":)" + processes + "}";
}

std::string goodRule(const std::string& id = "r") {
  return ruleJson(id, kTargets, "deny", kProcesses);
}

Messages described(const ParseResult& result) {
  Messages out;
  for (const auto& error : result.errors) {
    out.push_back(describe(error));
  }
  return out;
}

TEST(PolicyValidation, RejectsUnsupportedSchemaVersion) {
  const ParseResult result = parsePolicy(policyJson("", "2"));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result),
            Messages{"schemaVersion: unsupported schema version 2 (expected 1)"});
}

TEST(PolicyValidation, RejectsNegativeVersion) {
  const ParseResult result = parsePolicy(policyJson("", "1", "-1"));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), Messages{"version: must be >= 0"});
}

TEST(PolicyValidation, AcceptsVersionZero) {
  const ParseResult result = parsePolicy(policyJson("", "1", "0"));
  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result.policy->version, 0);
}

TEST(PolicyValidation, AcceptsEmptyRulesArray) {
  const ParseResult result = parsePolicy(policyJson(""));
  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result.policy->rules.empty());
}

TEST(PolicyValidation, RejectsEmptyAndDuplicateIds) {
  const ParseResult result = parsePolicy(
      policyJson(goodRule("a") + "," + goodRule("") + "," + goodRule("a") + "," + goodRule("b")));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result),
            (Messages{"rules[1].id: empty id", "rules[2].id: duplicate id 'a'"}));
}

TEST(PolicyValidation, RejectsEmptyTargets) {
  const ParseResult result = parsePolicy(policyJson(ruleJson("r", "[]", "deny", kProcesses)));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), Messages{"rules[0].targets: no targets"});
}

TEST(PolicyValidation, RejectsInvalidTargetGlobs) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {"", "empty target"},
      {"relative/x", "target must start with '/', '~' or '**'"},
      {"~bob/x", "'~' must be followed by '/' or end"},
      {"/a//b", "empty path segment"},
      {"/a/../b", "'.' and '..' segments are not allowed"},
      {"**x/y", "'**' must be a whole segment"},
      {"/a/", "trailing '/'"},
  };
  for (const auto& [target, message] : cases) {
    const ParseResult result = parsePolicy(
        policyJson(ruleJson("r", R"(["**/secret.txt",")" + target + R"("])", "deny", kProcesses)));
    EXPECT_FALSE(result.ok()) << target;
    EXPECT_EQ(described(result), Messages{"rules[0].targets[1]: " + message}) << target;
  }
}

TEST(PolicyValidation, RejectsUnknownAction) {
  const ParseResult result = parsePolicy(policyJson(ruleJson("r", kTargets, "allow", kProcesses)));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result),
            Messages{"rules[0].action: unsupported action 'allow' (expected 'deny')"});
}

TEST(PolicyValidation, RejectsEmptyProcesses) {
  const ParseResult result = parsePolicy(policyJson(ruleJson("r", kTargets, "deny", "[]")));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), Messages{"rules[0].processes: no processes"});
}

TEST(PolicyValidation, RejectsEmptyMatcher) {
  const ParseResult result = parsePolicy(
      policyJson(ruleJson("r", kTargets, "deny", R"([{"teamId":"X"},{"path":"/x"},{}])")));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), Messages{"rules[0].processes[2]: empty matcher"});
}

TEST(PolicyValidation, RejectsEmptyStringFields) {
  const ParseResult result = parsePolicy(policyJson(
      ruleJson("r", kTargets, "deny",
               R"([{"teamId":""},{"signingId":""},{"signingIdPrefix":""},{"path":""}])")));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), (Messages{"rules[0].processes[0].teamId: empty value",
                                         "rules[0].processes[1].signingId: empty value",
                                         "rules[0].processes[2].signingIdPrefix: empty value",
                                         "rules[0].processes[3].path: empty value"}));
}

TEST(PolicyValidation, RejectsRelativePathMatcher) {
  const ParseResult result =
      parsePolicy(policyJson(ruleJson("r", kTargets, "deny", R"([{"path":"usr/bin/python3"}])")));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), Messages{"rules[0].processes[0].path: must be absolute"});
}

TEST(PolicyValidation, ReportsAllSemanticErrorsTogether) {
  const ParseResult result = parsePolicy(
      policyJson(goodRule("a") + "," + ruleJson("a", "[]", "allow", "[{}]"), "2", "-5"));
  EXPECT_FALSE(result.ok());
  EXPECT_FALSE(result.policy.has_value());
  EXPECT_EQ(
      described(result),
      (Messages{"schemaVersion: unsupported schema version 2 (expected 1)", "version: must be >= 0",
                "rules[1].id: duplicate id 'a'", "rules[1].targets: no targets",
                "rules[1].action: unsupported action 'allow' (expected 'deny')",
                "rules[1].processes[0]: empty matcher"}));
}

TEST(PolicyValidation, StructuralAndSemanticErrorsCombine) {
  const ParseResult result = parsePolicy(policyJson(
      R"({"id":"","bogus":1,"targets":["**/secret.txt"],"action":"deny","processes":[{"teamId":"X"}]})"));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result),
            (Messages{"rules[0]: unknown field 'bogus'", "rules[0].id: empty id"}));
}

TEST(PolicyValidation, RejectsNonCanonicalMatcherPaths) {
  for (const char* path : {"/usr/bin/../bin/curl", "/usr/bin//scp", "/tmp/exfil", "/usr/bin/curl/",
                           "/usr/./bin/curl", "/var/x", "/etc/y"}) {
    const ParseResult result = parsePolicy(policyJson(
        ruleJson("r", kTargets, "deny", std::string(R"([{"path":")") + path + R"("}])")));
    EXPECT_FALSE(result.ok()) << path;
    EXPECT_EQ(described(result),
              Messages{"rules[0].processes[0].path: must be canonical (no '.', '..', '//', "
                       "trailing '/', or /tmp, /var, /etc alias prefix)"})
        << path;
  }
}

TEST(PolicyValidation, AcceptsCanonicalMatcherPaths) {
  for (const char* path : {"/usr/bin/python3", "/private/tmp/exfil", "/"}) {
    const ParseResult result = parsePolicy(policyJson(
        ruleJson("r", kTargets, "deny", std::string(R"([{"path":")") + path + R"("}])")));
    EXPECT_TRUE(result.ok()) << path;
  }
}

TEST(PolicyValidation, MisspelledMatcherFieldReportsUnknownAndEmpty) {
  const ParseResult result =
      parsePolicy(policyJson(ruleJson("r", kTargets, "deny", R"([{"teamID":"X"}])")));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), (Messages{"rules[0].processes[0]: unknown field 'teamID'",
                                         "rules[0].processes[0]: empty matcher"}));
}

TEST(PolicyValidation, RejectsDuplicateRootKeys) {
  const ParseResult result =
      parsePolicy(R"({"schemaVersion":1,"version":1,"rules":[],"rules":[],"version":2})");
  EXPECT_FALSE(result.ok());
  EXPECT_FALSE(result.policy.has_value());
  EXPECT_EQ(described(result),
            (Messages{"$: duplicate key 'rules'", "$: duplicate key 'version'"}));
}

TEST(PolicyValidation, RejectsDuplicateKeysInRuleAndMatcher) {
  const std::string rule = R"({"id":"r","targets":["**/a"],"targets":["**/b"],"action":"deny",)"
                           R"("processes":[{"teamId":"X","teamId":"Y"}]})";
  const ParseResult result = parsePolicy(policyJson(rule));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(described(result), (Messages{"rules[0]: duplicate key 'targets'",
                                         "rules[0].processes[0]: duplicate key 'teamId'"}));
}

TEST(PolicyValidation, SameKeysInSiblingObjectsAreNotDuplicates) {
  const ParseResult result = parsePolicy(policyJson(goodRule("a") + "," + goodRule("b")));
  EXPECT_TRUE(result.ok());
}

}  // namespace
