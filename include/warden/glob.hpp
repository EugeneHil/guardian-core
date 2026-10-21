#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace warden {

/// Matches a canonical absolute `path` against a target glob (already `~`-expanded).
/// Both are split on `/`. A leading `/` in the pattern requires a leading `/` in the path;
/// a pattern without one (`**/...`) matches at any depth. A `**` segment matches zero or more
/// whole segments; `*` inside a segment matches any run of non-`/` characters. Everything else
/// is literal and case-sensitive. Allocation-free, iterative, O(segments * pattern) worst case.
bool globMatch(std::string_view pattern, std::string_view path) noexcept;

/// Validates a *target* glob (before `~` expansion). Returns a message, or nullopt when valid.
std::optional<std::string> globError(std::string_view target);

}  // namespace warden
