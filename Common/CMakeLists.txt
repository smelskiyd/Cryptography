set(SOURCES
        include/profile.h
        include/test_runner.h
        include/json.h             src/json.cpp)

add_library(DevUtils STATIC ${SOURCES})

set_target_properties(DevUtils PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(DevUtils PUBLIC include)
