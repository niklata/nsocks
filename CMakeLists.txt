project (nsocks)

cmake_minimum_required (VERSION 2.6)

####################################

# Computes the realtionship between two version strings.  A version
# string is a number delineated by '.'s such as 1.3.2 and 0.99.9.1.
# You can feed version strings with different number of dot versions,
# and the shorter version number will be padded with zeros: 9.2 <
# 9.2.1 will actually compare 9.2.0 < 9.2.1.
#
# Input: a_in - value, not variable
#        b_in - value, not variable
#        result_out - variable with value:
#                         -1 : a_in <  b_in
#                          0 : a_in == b_in
#                          1 : a_in >  b_in
#
# Written by James Bigler.
MACRO(COMPARE_VERSION_STRINGS a_in b_in result_out)
  # Since SEPARATE_ARGUMENTS using ' ' as the separation token,
  # replace '.' with ' ' to allow easy tokenization of the string.
  STRING(REPLACE "." " " a ${a_in})
  STRING(REPLACE "." " " b ${b_in})
  SEPARATE_ARGUMENTS(a)
  SEPARATE_ARGUMENTS(b)

  # Check the size of each list to see if they are equal.
  LIST(LENGTH a a_length)
  LIST(LENGTH b b_length)

  # Pad the shorter list with zeros.

  # Note that range needs to be one less than the length as the for
  # loop is inclusive (silly CMake).
  IF(a_length LESS b_length)
    # a is shorter
    SET(shorter a)
    MATH(EXPR range "${b_length} - 1")
    MATH(EXPR pad_range "${b_length} - ${a_length} - 1")
  ELSE(a_length LESS b_length)
    # b is shorter
    SET(shorter b)
    MATH(EXPR range "${a_length} - 1")
    MATH(EXPR pad_range "${a_length} - ${b_length} - 1")
  ENDIF(a_length LESS b_length)

  # PAD out if we need to
  IF(NOT pad_range LESS 0)
    FOREACH(pad RANGE ${pad_range})
      # Since shorter is an alias for b, we need to get to it by by dereferencing shorter.
      LIST(APPEND ${shorter} 0)
    ENDFOREACH(pad RANGE ${pad_range})
  ENDIF(NOT pad_range LESS 0)

  SET(result 0)
  FOREACH(index RANGE ${range})
    IF(result EQUAL 0)
      # Only continue to compare things as long as they are equal
      LIST(GET a ${index} a_version)
      LIST(GET b ${index} b_version)
      # LESS
      IF(a_version LESS b_version)
        SET(result -1)
      ENDIF(a_version LESS b_version)
      # GREATER
      IF(a_version GREATER b_version)
        SET(result 1)
      ENDIF(a_version GREATER b_version)
    ENDIF(result EQUAL 0)
  ENDFOREACH(index)

  # Copy out the return result
  SET(${result_out} ${result})
ENDMACRO(COMPARE_VERSION_STRINGS)

####################################

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu99 -pedantic -Wall -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wpointer-arith -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=gnu++0x -pedantic -Wall -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wpointer-arith -Wno-unused-parameter")

if (WIN32)
  set(OSNAME "Win32")
else()
execute_process(
  COMMAND uname
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE OSNAME
  )
endif()
#message("OSNAME: '${OSNAME}'")

if (${OSNAME} STREQUAL "Linux")
  message("Detected that the current host is a Linux system.")
  execute_process(
    COMMAND uname -r
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE LINUX_VERSION
    )
  COMPARE_VERSION_STRINGS(${LINUX_VERSION} "2.6.21" LINUX_HAS_SPLICE)
  if (NOT ${LINUX_HAS_SPLICE} LESS 0)
    message("Enabling use of splice() syscall for zerocopy proxying!")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_SPLICE")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_SPLICE")
  else()
    message("splice() not available.  Proxying with a memory buffer and send()/recv().")
  endif()
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
  message("Detected that the current host is a 64-bit system.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAS_64BIT")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAS_64BIT")
endif()

include_directories("${PROJECT_SOURCE_DIR}"
                    "${PROJECT_SOURCE_DIR}/ncmlib"
                    "${PROJECT_SOURCE_DIR}/cppformat")
add_subdirectory(ncmlib)
add_subdirectory(cppformat)

find_package( Boost COMPONENTS system program_options )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )
find_package(Threads)

set(NSOCKS_SRCS
  socksclient.cpp
  nsocks.cpp
  )

add_executable(nsocks ${NSOCKS_SRCS})
target_link_libraries(nsocks ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES}
                      ncmlib cppformat)

