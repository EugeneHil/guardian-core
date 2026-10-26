#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace guardian {

enum class Action : std::uint8_t { Deny };

/// All present fields must match (logical AND). A matcher with no field never matches.
struct ProcessMatcher {
  std::optional<std::string> teamId;
  std::optional<std::string> signingId;
  std::optional<std::string> signingIdPrefix;
  std::optional<std::string> path;
};

struct Rule {
  std::string id;
  std::string description;
  std::vector<std::string> targets;
  Action action = Action::Deny;
  std::vector<ProcessMatcher> processes;
};

struct Policy {
  int schemaVersion = 1;
  std::int64_t version = 0;
  std::vector<Rule> rules;
};

/// An empty string means "absent" (e.g. an unsigned process has no teamId).
struct ProcessInfo {
  std::string path;
  std::string signingId;
  std::string teamId;
};

struct AccessRequest {
  std::string filePath;
  ProcessInfo process;
  std::optional<ProcessInfo> responsible;
};

enum class Verdict : std::uint8_t { Allow, Deny };

struct Decision {
  Verdict verdict = Verdict::Allow;
  std::string ruleId;  // empty on Allow
};

struct ValidationError {
  std::string path;
  std::string message;
};

}  // namespace guardian
