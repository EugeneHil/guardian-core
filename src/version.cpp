#include "warden/version.hpp"

namespace warden {

std::string_view coreVersion() noexcept { return WARDEN_CORE_VERSION; }

}  // namespace warden
