# Warnings are errors in every build.
add_library(guardian_warnings INTERFACE)
if(MSVC)
    target_compile_options(guardian_warnings INTERFACE /W4 /WX)
else()
    target_compile_options(guardian_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Werror)
endif()
