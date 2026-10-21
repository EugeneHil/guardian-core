# Warnings are errors in every build.
add_library(warden_warnings INTERFACE)
if(MSVC)
    target_compile_options(warden_warnings INTERFACE /W4 /WX)
else()
    target_compile_options(warden_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Werror)
endif()
