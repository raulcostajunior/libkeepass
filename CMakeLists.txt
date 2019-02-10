cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

project (KeePassLib
    LANGUAGES
      CXX
    )

set (CMAKE_CXX_STANDARD 11)

add_library (keepass_objs
    OBJECT
      KeePassFile.h
      KeePassFile.cpp
    )

set_target_properties(keepass_objs
    PROPERTIES
      POSITION_INDEPENDENT_CODE 1
    )

add_library (keepass_static
    STATIC
      $<TARGET_OBJECTS:keepass_objs>
    )

set_target_properties(keepass_static
    PROPERTIES
      OUTPUT_NAME "keepass"
    )

add_library(keepass_shared
    SHARED
      $<TARGET_OBJECTS:keepass_objs>
    )

set_target_properties(keepass_shared
    PROPERTIES
      OUTPUT_NAME "keepass"
    )

add_executable(keepassConsole
    keepassConsole.cpp
    )

target_link_libraries(keepassConsole
    keepass_static
    )



