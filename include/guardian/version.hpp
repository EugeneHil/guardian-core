#pragma once

#include <string_view>

namespace guardian {

/// Semantic version of guardian-core (the CMake PROJECT_VERSION).
std::string_view coreVersion() noexcept;

}  // namespace guardian
