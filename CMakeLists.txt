cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (KeePassLib
    LANGUAGES
      CXX
    )

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library (keepass_objs
    OBJECT
      src/KeePassFileException.h
      src/KeePassFileException.cpp
      src/KeePassFile.h
      src/KeePassFile.cpp
      src/KeePassFileSettings.h
      src/KeePassFileSettings.cpp
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

# add_executable(unit_tests unit_tests.cpp)
# target_link_libraries(unit_tests keepass_static)

#add_custom_command(TARGET unit_tests POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy_directory
#                       ${CMAKE_SOURCE_DIR}/db_samples $<TARGET_FILE_DIR:unit_tests>)

#enable_testing()

#add_test (
#    NAME unit_tests
#    COMMAND $<TARGET_FILE:unit_tests> --success
#    )

