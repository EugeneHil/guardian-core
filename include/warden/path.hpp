#pragma once

#include <string>
#include <string_view>

namespace warden {

/// Lexical normalization: collapses `//`, drops `.`, resolves `..` (never above root),
/// drops a trailing `/`, and rewrites a leading /tmp, /var or /etc segment to /private/....
/// Relative paths are cleaned but not rooted. Never throws on well-formed input views.
std::string normalizePath(std::string_view path);

/// True iff `path` is absolute, free of empty/`.`/`..` segments and trailing `/`
/// (except root) and does not start with an alias prefix. Allocation-free.
bool isCanonicalPath(std::string_view path) noexcept;

/// `~` -> `/Users/*`, `~/rest` -> `/Users/*/rest`; everything else is unchanged.
std::string expandTarget(std::string_view target);

}  // namespace warden
