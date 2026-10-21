#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <warden/policy.hpp>

namespace warden {

/// `policy` has a value iff `errors` is empty.
struct ParseResult {
  std::optional<Policy> policy;
  std::vector<ValidationError> errors;

  [[nodiscard]] bool ok() const noexcept { return policy.has_value(); }
};

/// Parses and validates a policy document. Reports all errors found; never throws
/// (except std::bad_alloc).
ParseResult parsePolicy(std::string_view json);

/// "<path>: <message>".
std::string describe(const ValidationError& error);

}  // namespace warden
