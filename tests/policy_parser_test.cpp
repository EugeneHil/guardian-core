#include <gtest/gtest.h>

#include <string>
#include <guardian/engine.hpp>
#include <guardian/policy_parser.hpp>

#include "test_support.hpp"

namespace {

using guardian::describe;
using guardian::parsePolicy;
using guardian::ParseResult;
using guardian::ValidationError;

const char* const kSpecJson = R"({
  "schemaVersion": 1,
  "version": 3,
  "rules": [
    { "id": "secrets-from-browsers-and-ai",
      "description": ".env files and SSH keys must not be read by browsers and AI apps",
      "targets": ["**/.env", "**/.env.*", "~/.ssh/**"],
      "action": "deny",
      "processes": [
        { "teamId": "EQHXZ8M8AV" },
        { "signingIdPrefix": "com.google.Chrome" },
        { "signingIdPrefix": "com.apple.Safari" },
        { "signingIdPrefix": "com.openai.chat" },
        { "signingIdPrefix": "com.anthropic.claude" },
        { "path": "/usr/bin/python3" }
      ] }
  ]
})";

std::string ruleWith(const std::string& body) {
  return R"({"schemaVersion":1,"version":1,"rules":[)" + body + "]}";
}

const char* const kGoodRule =
    R"({"id":"r","targets":["**/.env"],"action":"deny","processes":[{"teamId":"X"}]})";

bool hasError(const ParseResult& result, const std::string& path, const std::string& message) {
  for (const ValidationError& error : result.errors) {
    if (error.path == path && error.message == message) {
      return true;
    }
  }
  return false;
}

TEST(PolicyParser, ParsesSpecExample) {
  ParseResult result = parsePolicy(kSpecJson);
  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result.errors.empty());
  const guardian::Policy& policy = *result.policy;
  EXPECT_EQ(policy.schemaVersion, 1);
  EXPECT_EQ(policy.version, 3);
  ASSERT_EQ(policy.rules.size(), 1U);
  const guardian::Rule& rule = policy.rules[0];
  EXPECT_EQ(rule.id, "secrets-from-browsers-and-ai");
  EXPECT_EQ(rule.targets.size(), 3U);
  ASSERT_EQ(rule.processes.size(), 6U);
  EXPECT_EQ(rule.processes[0].teamId, "EQHXZ8M8AV");
  EXPECT_EQ(rule.processes[5].path, "/usr/bin/python3");

  guardian::Engine engine(*result.policy);
  guardian::ProcessInfo chrome;
  chrome.path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  chrome.signingId = "com.google.Chrome";
  chrome.teamId = "EQHXZ8M8AV";
  guardian::Decision decision = engine.evaluate(guardian::makeRequest("/Users/bob/.env", chrome));
  EXPECT_EQ(decision.verdict, guardian::Verdict::Deny);
  EXPECT_EQ(decision.ruleId, "secrets-from-browsers-and-ai");
}

TEST(PolicyParser, DescriptionIsOptional) {
  ParseResult result = parsePolicy(ruleWith(kGoodRule));
  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result.policy->rules[0].description, "");
}

TEST(PolicyParser, InvalidJsonIsOneErrorAtRoot) {
  for (const char* text : {"{", ""}) {
    ParseResult result = parsePolicy(text);
    EXPECT_FALSE(result.ok());
    ASSERT_EQ(result.errors.size(), 1U);
    EXPECT_EQ(result.errors[0].path, "$");
    EXPECT_EQ(result.errors[0].message.rfind("invalid JSON", 0), 0U);
  }
}

TEST(PolicyParser, RootMustBeObject) {
  for (const char* text : {"[]", "3", "null"}) {
    ParseResult result = parsePolicy(text);
    EXPECT_FALSE(result.ok());
    ASSERT_EQ(result.errors.size(), 1U);
    EXPECT_EQ(describe(result.errors[0]), "$: expected object");
  }
}

TEST(PolicyParser, ReportsMissingFields) {
  ParseResult result = parsePolicy("{}");
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.errors.size(), 3U);
  EXPECT_TRUE(hasError(result, "schemaVersion", "missing"));
  EXPECT_TRUE(hasError(result, "version", "missing"));
  EXPECT_TRUE(hasError(result, "rules", "missing"));
}

TEST(PolicyParser, ReportsWrongTypes) {
  ParseResult result = parsePolicy(R"({"schemaVersion":"1","version":1.5,"rules":{}})");
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.errors.size(), 3U);
  EXPECT_TRUE(hasError(result, "schemaVersion", "expected integer"));
  EXPECT_TRUE(hasError(result, "version", "expected integer"));
  EXPECT_TRUE(hasError(result, "rules", "expected array"));
}

TEST(PolicyParser, RejectsIntegersBeyondInt64) {
  ParseResult result =
      parsePolicy(R"({"schemaVersion":1,"version":18446744073709551615,"rules":[]})");
  EXPECT_FALSE(result.ok());
  ASSERT_EQ(result.errors.size(), 1U);
  EXPECT_EQ(describe(result.errors[0]), "version: expected integer");
}

TEST(PolicyParser, RejectsSchemaVersionOutOfIntRange) {
  ParseResult result = parsePolicy(R"({"schemaVersion":4294967297,"version":1,"rules":[]})");
  EXPECT_FALSE(result.ok());
  ASSERT_EQ(result.errors.size(), 1U);
  EXPECT_EQ(describe(result.errors[0]), "schemaVersion: expected integer");
}

TEST(PolicyParser, ReportsRuleFieldErrors) {
  ParseResult result = parsePolicy(
      ruleWith(R"({"id":5,"description":1,"targets":["/a",2],"action":"deny","processes":[3]})"));
  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(hasError(result, "rules[0].id", "expected string"));
  EXPECT_TRUE(hasError(result, "rules[0].description", "expected string"));
  EXPECT_TRUE(hasError(result, "rules[0].targets[1]", "expected string"));
  EXPECT_TRUE(hasError(result, "rules[0].processes[0]", "expected object"));
  EXPECT_EQ(result.errors.size(), 4U);
}

TEST(PolicyParser, ReportsMissingRuleFieldsAndNonObjectRule) {
  ParseResult result = parsePolicy(ruleWith("{},7"));
  EXPECT_FALSE(result.ok());
  EXPECT_TRUE(hasError(result, "rules[0].id", "missing"));
  EXPECT_TRUE(hasError(result, "rules[0].targets", "missing"));
  EXPECT_TRUE(hasError(result, "rules[0].action", "missing"));
  EXPECT_TRUE(hasError(result, "rules[0].processes", "missing"));
  EXPECT_TRUE(hasError(result, "rules[1]", "expected object"));
  EXPECT_EQ(result.errors.size(), 5U);
}

TEST(PolicyParser, RejectsUnsupportedAction) {
  ParseResult result = parsePolicy(
      ruleWith(R"({"id":"r","targets":["/a"],"action":"allow","processes":[{"teamId":"X"}]})"));
  EXPECT_FALSE(result.ok());
  ASSERT_EQ(result.errors.size(), 1U);
  EXPECT_EQ(describe(result.errors[0]),
            "rules[0].action: unsupported action 'allow' (expected 'deny')");
}

TEST(PolicyParser, ReportsMatcherFieldTypes) {
  ParseResult result = parsePolicy(ruleWith(
      R"({"id":"r","targets":["/a"],"action":"deny","processes":[{"teamId":1,"path":"/x"}]})"));
  EXPECT_FALSE(result.ok());
  ASSERT_EQ(result.errors.size(), 1U);
  EXPECT_EQ(describe(result.errors[0]), "rules[0].processes[0].teamId: expected string");
}

TEST(PolicyParser, CollectsErrorsAcrossRules) {
  ParseResult result = parsePolicy(
      ruleWith(R"({"id":1,"targets":["/a"],"action":"deny","processes":[{"teamId":"X"}]},)"
               R"({"id":"b","targets":["/a"],"action":"deny","processes":[{"teamId":false}]})"));
  EXPECT_FALSE(result.ok());
  EXPECT_FALSE(result.policy.has_value());
  EXPECT_TRUE(hasError(result, "rules[0].id", "expected string"));
  EXPECT_TRUE(hasError(result, "rules[1].processes[0].teamId", "expected string"));
  EXPECT_EQ(result.errors.size(), 2U);
}

TEST(PolicyParser, RejectsUnknownKeys) {
  ParseResult root = parsePolicy(R"({"schemaVersion":1,"version":1,"rules":[],"extra":1})");
  EXPECT_FALSE(root.ok());
  ASSERT_EQ(root.errors.size(), 1U);
  EXPECT_EQ(root.errors[0].path, "extra");
  EXPECT_EQ(root.errors[0].message, "unknown field 'extra'");

  ParseResult matcher = parsePolicy(ruleWith(
      R"({"id":"r","targets":["/a"],"action":"deny","processes":[{"teamId":"X","teamID":"X"}]})"));
  EXPECT_FALSE(matcher.ok());
  ASSERT_EQ(matcher.errors.size(), 1U);
  EXPECT_EQ(describe(matcher.errors[0]), "rules[0].processes[0]: unknown field 'teamID'");

  ParseResult rule = parsePolicy(ruleWith(
      R"({"id":"r","targets":["/a"],"action":"deny","processes":[{"teamId":"X"}],"bogus":null})"));
  ASSERT_EQ(rule.errors.size(), 1U);
  EXPECT_EQ(describe(rule.errors[0]), "rules[0]: unknown field 'bogus'");
}

TEST(PolicyParser, RejectsTooDeepNesting) {
  std::string deep(100000, '[');
  ParseResult result = parsePolicy(deep);
  EXPECT_FALSE(result.ok());
  ASSERT_EQ(result.errors.size(), 1U);
  EXPECT_EQ(describe(result.errors[0]), "$: nesting too deep");
}

TEST(PolicyParser, BracketsInsideStringsDoNotCountAsNesting) {
  std::string text =
      R"({"schemaVersion":1,"version":1,"rules":[],"x":")" + std::string(200, '[') + R"("})";
  ParseResult result = parsePolicy(text);
  ASSERT_EQ(result.errors.size(), 1U);
  EXPECT_EQ(result.errors[0].message, "unknown field 'x'");
}

TEST(PolicyParser, DescribeFormatsPathAndMessage) {
  ValidationError error{"rules[0].processes[2]", "empty matcher"};
  EXPECT_EQ(describe(error), "rules[0].processes[2]: empty matcher");
}

}  // namespace
