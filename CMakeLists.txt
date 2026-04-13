cmake_minimum_required(VERSION 3.20)

# Global properties
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Project name
project(cpptrader)

# Doxygen
find_package(Doxygen)
if(DOXYGEN_FOUND)
  set(DOXYGEN "doxygen")
  if(NOT TARGET ${DOXYGEN})
    add_custom_command(OUTPUT "Doxyfile" COMMAND ${DOXYGEN_EXECUTABLE} "Doxyfile" WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/documents")
    add_custom_target(${DOXYGEN} DEPENDS "Doxyfile")
    set_target_properties(${DOXYGEN} PROPERTIES FOLDER "doxygen")
  endif()
endif()

# CMake module path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Compiler features
include(SetCompilerFeatures)
include(SetCompilerWarnings)
include(SetPlatformFeatures)
include(SystemInformation)

# Modules
add_subdirectory("modules")

# Link libraries
list(APPEND LINKLIBS cppcommon)

# System directories
include_directories(SYSTEM "${CMAKE_CURRENT_SOURCE_DIR}/modules")

# Library
file(GLOB_RECURSE LIB_HEADER_FILES "include/*.h" "source/*.h")
file(GLOB_RECURSE LIB_INLINE_FILES "include/*.inl" "source/*.inl")
file(GLOB_RECURSE LIB_SOURCE_FILES "include/*.cpp" "source/*.cpp")
add_library(cpptrader ${LIB_HEADER_FILES} ${LIB_INLINE_FILES} ${LIB_SOURCE_FILES})
set_target_properties(cpptrader PROPERTIES COMPILE_FLAGS "${PEDANTIC_COMPILE_FLAGS}" FOLDER "libraries")
target_include_directories(cpptrader PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(cpptrader ${LINKLIBS})
list(APPEND INSTALL_TARGETS cpptrader)
list(APPEND LINKLIBS cpptrader)

# Additional module components: benchmarks, examples, plugins, tests, tools and install
if(NOT CPPTRADER_MODULE)

# Applications
file(GLOB APP_HEADER_FILES "app/*.h")
file(GLOB APP_INLINE_FILES "app/*.inl")
file(GLOB APP_SOURCE_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/app" "app/*.cpp")
foreach(APP_SOURCE_FILE ${APP_SOURCE_FILES})
  string(REGEX REPLACE "(.*)\\.cpp" "\\1" APP_NAME ${APP_SOURCE_FILE})
  set(APP_TARGET "cpptrader-app-${APP_NAME}")
  add_executable(${APP_TARGET} ${APP_HEADER_FILES} ${APP_INLINE_FILES} "app/${APP_SOURCE_FILE}")
  set_target_properties(${APP_TARGET} PROPERTIES COMPILE_FLAGS "${PEDANTIC_COMPILE_FLAGS}" FOLDER "app")
  target_link_libraries(${APP_TARGET} ${LINKLIBS})
  list(APPEND INSTALL_TARGETS ${APP_TARGET})
  list(APPEND INSTALL_TARGETS_PDB ${APP_TARGET})
endforeach()

  # Benchmarks
  file(GLOB BENCHMARK_HEADER_FILES "performance/*.h")
  file(GLOB BENCHMARK_INLINE_FILES "performance/*.inl")
  file(GLOB BENCHMARK_SOURCE_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/performance" "performance/*.cpp")
  foreach(BENCHMARK_SOURCE_FILE ${BENCHMARK_SOURCE_FILES})
    string(REGEX REPLACE "(.*)\\.cpp" "\\1" BENCHMARK_NAME ${BENCHMARK_SOURCE_FILE})
    set(BENCHMARK_TARGET "cpptrader-performance-${BENCHMARK_NAME}")
    add_executable(${BENCHMARK_TARGET} ${BENCHMARK_HEADER_FILES} ${BENCHMARK_INLINE_FILES} "performance/${BENCHMARK_SOURCE_FILE}")
    set_target_properties(${BENCHMARK_TARGET} PROPERTIES COMPILE_FLAGS "${PEDANTIC_COMPILE_FLAGS}" FOLDER "performance")
    target_link_libraries(${BENCHMARK_TARGET} ${LINKLIBS} cppbenchmark)
    list(APPEND INSTALL_TARGETS ${BENCHMARK_TARGET})
    list(APPEND INSTALL_TARGETS_PDB ${BENCHMARK_TARGET})
  endforeach()

  # Tests
  file(GLOB TESTS_HEADER_FILES "tests/*.h")
  file(GLOB TESTS_INLINE_FILES "tests/*.inl")
  file(GLOB TESTS_SOURCE_FILES "tests/*.cpp")
  add_executable(cpptrader-tests ${TESTS_HEADER_FILES} ${TESTS_INLINE_FILES} ${TESTS_SOURCE_FILES})
  set_target_properties(cpptrader-tests PROPERTIES COMPILE_FLAGS "${PEDANTIC_COMPILE_FLAGS}" FOLDER "tests")
  target_include_directories(cpptrader-tests PRIVATE Catch2)
  target_link_libraries(cpptrader-tests ${LINKLIBS} Catch2)
  list(APPEND INSTALL_TARGETS cpptrader-tests)
  list(APPEND INSTALL_TARGETS_PDB cpptrader-tests)

  # CTest
  enable_testing()
  add_test(cpptrader-tests cpptrader-tests --durations yes --order lex)

  # Install
  install(TARGETS ${INSTALL_TARGETS}
    RUNTIME DESTINATION "${PROJECT_SOURCE_DIR}/bin"
    LIBRARY DESTINATION "${PROJECT_SOURCE_DIR}/bin"
    ARCHIVE DESTINATION "${PROJECT_SOURCE_DIR}/bin")

  # Install *.pdb files
  if(MSVC)
    foreach(INSTALL_TARGET_PDB ${INSTALL_TARGETS_PDB})
      install(FILES $<TARGET_PDB_FILE:${INSTALL_TARGET_PDB}> DESTINATION "${PROJECT_SOURCE_DIR}/bin")
    endforeach()
  endif()

endif()
