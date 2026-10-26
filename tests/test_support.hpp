#pragma once

#include <optional>
#include <string>
#include <utility>
#include <guardian/policy.hpp>

namespace guardian {

inline Policy makeSpecPolicy() {
  Policy policy;
  policy.version = 3;
  Rule rule;
  rule.id = "secrets-from-browsers-and-ai";
  rule.description = "Keep secrets away from browsers and AI clients";
  rule.targets = {"**/.env", "**/.env.*", "~/.ssh/**"};
  rule.action = Action::Deny;
  ProcessMatcher team;
  team.teamId = "EQHXZ8M8AV";
  rule.processes.push_back(team);
  for (const char* prefix :
       {"com.google.Chrome", "com.apple.Safari", "com.openai.chat", "com.anthropic.claude"}) {
    ProcessMatcher matcher;
    matcher.signingIdPrefix = prefix;
    rule.processes.push_back(matcher);
  }
  ProcessMatcher python;
  python.path = "/usr/bin/python3";
  rule.processes.push_back(python);
  policy.rules.push_back(std::move(rule));
  return policy;
}

inline AccessRequest makeRequest(std::string file, ProcessInfo process,
                                 std::optional<ProcessInfo> responsible = std::nullopt) {
  AccessRequest request;
  request.filePath = std::move(file);
  request.process = std::move(process);
  request.responsible = std::move(responsible);
  return request;
}

}  // namespace guardian
