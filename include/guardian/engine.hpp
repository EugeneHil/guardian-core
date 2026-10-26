#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <guardian/policy.hpp>

namespace guardian {

/// True iff `matcher` has at least one field and every present field is non-empty and matches
/// `process` (`teamId`/`signingId`/`path` exactly, `signingIdPrefix` as a prefix). An empty
/// `ProcessInfo` value never matches a present field.
bool matchesProcess(const ProcessMatcher& matcher, const ProcessInfo& process) noexcept;

/// Immutable policy evaluator; safe to share across threads.
class Engine {
 public:
  explicit Engine(Policy policy);

  /// Normalizes the path, then the first rule whose target matches and whose matcher matches
  /// the process or the responsible process denies. Otherwise allows.
  [[nodiscard]] Decision evaluate(const AccessRequest& request) const;

  /// Conservative, allocation-free prefilter: never false for a path `evaluate` could deny.
  [[nodiscard]] bool isPotentiallyProtected(std::string_view path) const noexcept;

  [[nodiscard]] const Policy& policy() const noexcept { return policy_; }

 private:
  Policy policy_;
  std::vector<std::vector<std::string>> patterns_;  // aligned with policy_.rules
};

/// Equivalent to `Engine(policy).evaluate(request)`.
Decision evaluate(const Policy& policy, const AccessRequest& request);

}  // namespace guardian
