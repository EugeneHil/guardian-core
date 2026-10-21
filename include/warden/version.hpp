#pragma once

#include <string_view>

namespace warden {

/// Semantic version of warden-core (the CMake PROJECT_VERSION).
std::string_view coreVersion() noexcept;

}  // namespace warden
