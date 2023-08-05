
find_package(spdlog REQUIRED)
find_package(elfio REQUIRED)

add_executable(rparse main.cpp)
target_link_libraries(rparse PRIVATE spdlog::spdlog elfio::elfio)
target_include_directories(rparse PRIVATE ${CMAKE_SOURCE_DIR}/include/)
