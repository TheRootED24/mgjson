cmake_minimum_required(VERSION 3.1...3.27)

#-------------------------------------------------------------------------------
# Build Environment
#-------------------------------------------------------------------------------

 add_definitions(-fpic -W -DMG_ENABLE_LINES)
 add_compile_options(-W -Wall -Werror -Wextra)

project(
  mgjson
  VERSION 7.14
  LANGUAGES C
  )


add_library(mgjson SHARED mgjson.c)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
target_link_libraries(mgjson m)
install(TARGETS mgjson DESTINATION /usr/lib/)
