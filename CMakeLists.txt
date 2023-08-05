cmake_minimum_required(VERSION 3.26)

project(rparse CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_IPO "Enable Interprocedural Optimization, aka Link Time Optimization (LTO)" OFF)
if(ENABLE_IPO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT result OUTPUT output)
  if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(SEND_ERROR "IPO is not supported: ${output}")
  endif()
endif()

set(CMAKE_CXX_STANDARD_REQUIRED 20)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -stdlib=libc++ \
    -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wpedantic \
    -Wconversion -Wsign-conversion -Wnull-dereference -Wdouble-promotion -Wformat=2 -Wmisleading-indentation \
    -fno-omit-frame-pointer -fsanitize=address")
endif()

option(ENABLE_COVERAGE "Enable coverage reporting for gcc/clang" OFF)
if(ENABLE_COVERAGE)
  target_compile_options(${PROJECT_NAME} INTERFACE --coverage -O0 -g)
  target_link_libraries(${PROJECT_NAME} INTERFACE --coverage)
endif()

option(ENABLE_DOXYGEN "Enable doxygen doc builds of source" OFF)
if(ENABLE_DOXYGEN)
  set(DOXYGEN_CALLER_GRAPH YES)
  set(DOXYGEN_CALL_GRAPH YES)
  set(DOXYGEN_EXTRACT_ALL YES)

  find_package(Doxygen REQUIRED)
  doxygen_add_docs(docs ${PROJECT_SOURCE_DIR} ALL COMMENT "Generate documentation.")
endif()

option(ENABLE_TESTING "Enable Test Builds" OFF)
option(ENABLE_FUZZING "Enable Fuzzing Builds" OFF)

add_subdirectory(src)

if(ENABLE_TESTING)
  enable_testing()
  message("Building Tests.")
  add_subdirectory(test)
endif()

if(ENABLE_FUZZING)
  message("Building Fuzz Tests.")
  add_subdirectory(fuzz_test)
endif()
