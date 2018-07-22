cmake_minimum_required (VERSION 3.0)

project (KeePassLib)

include_directories (${PROJECT_SOURCE_DIR})

add_library (keepass STATIC KeePassFile.cpp)

