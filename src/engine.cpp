#include <algorithm>
#include <cstddef>
#include <guardian/engine.hpp>
#include <guardian/glob.hpp>
#include <guardian/path.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace guardian {

namespace {

bool fieldMatches(const std::optional<std::string>& expected, const std::string& actual) noexcept {
  return !expected.has_value() || (!expected->empty() && !actual.empty() && *expected == actual);
}

bool prefixMatches(const std::optional<std::string>& prefix, const std::string& actual) noexcept {
  if (!prefix.has_value()) {
    return true;
  }
  return !prefix->empty() && actual.size() >= prefix->size() &&
         std::equal(prefix->begin(), prefix->end(), actual.begin());
}

bool anyMatcher(const std::vector<ProcessMatcher>& matchers, const ProcessInfo& process) noexcept {
  return std::any_of(matchers.begin(), matchers.end(), [&process](const ProcessMatcher& matcher) {
    return matchesProcess(matcher, process);
  });
}

}  // namespace

bool matchesProcess(const ProcessMatcher& matcher, const ProcessInfo& process) noexcept {
  if (!matcher.teamId && !matcher.signingId && !matcher.signingIdPrefix && !matcher.path) {
    return false;
  }
  return fieldMatches(matcher.teamId, process.teamId) &&
         fieldMatches(matcher.signingId, process.signingId) &&
         prefixMatches(matcher.signingIdPrefix, process.signingId) &&
         fieldMatches(matcher.path, process.path);
}

Engine::Engine(Policy policy) : policy_(std::move(policy)) {
  patterns_.reserve(policy_.rules.size());
  for (const Rule& rule : policy_.rules) {
    std::vector<std::string> compiled;
    compiled.reserve(rule.targets.size());
    for (const std::string& target : rule.targets) {
      compiled.push_back(normalizePath(expandTarget(target)));
    }
    patterns_.push_back(std::move(compiled));
  }
}

Decision Engine::evaluate(const AccessRequest& request) const {
  const std::string path = normalizePath(request.filePath);
  for (std::size_t i = 0; i < policy_.rules.size(); ++i) {
    const Rule& rule = policy_.rules[i];
    bool targetMatches = false;
    for (const std::string& pattern : patterns_[i]) {
      if (globMatch(pattern, path)) {
        targetMatches = true;
        break;
      }
    }
    if (!targetMatches) {
      continue;
    }
    if (anyMatcher(rule.processes, request.process) ||
        (request.responsible && anyMatcher(rule.processes, *request.responsible))) {
      Decision decision;
      decision.verdict = Verdict::Deny;
      decision.ruleId = rule.id;
      return decision;
    }
  }
  return Decision{};
}

bool Engine::isPotentiallyProtected(std::string_view path) const noexcept {
  if (!isCanonicalPath(path)) {
    return true;
  }
  for (const std::vector<std::string>& group : patterns_) {
    for (const std::string& pattern : group) {
      if (globMatch(pattern, path)) {
        return true;
      }
    }
  }
  return false;
}

Decision evaluate(const Policy& policy, const AccessRequest& request) {
  return Engine(policy).evaluate(request);
}

}  // namespace guardian
