# Find the Silicon Labs EZMESH location
# =============================================================================
# Usage of this module is as follows:
#
# find_package(EZMESH)
#
# cmake-format: off
# Variables used by this module:
#
# Variables defined by this module:
# * EZMESH_FOUND - True if the EZMESH sources are found.
# cmake-format: on
# =============================================================================
if(EZMESH_LOCATION)
  set(FETCHCONTENT_SOURCE_DIR_EZMESH CMAKE_SOURCE_DIR "${EZMESH_LOCATION}")
  message(STATUS "Found EZMESH at ${EZMESH_LOCATION}")
elseif(DEFINED ENV{EZMESH_LOCATION})
    set(FETCHCONTENT_SOURCE_DIR_EZMESH "$ENV{EZMESH_LOCATION}")
    message(STATUS "EZMESH - using provided EZMESH_LOCATION ($ENV{EZMESH_LOCATION})")
else()
  if(NOT FETCH_EZMESH_VERSION)
    # The version to fetch should ideally be the same as the version used for fetching GeckoSDK
    set(FETCH_EZMESH_VERSION "v4.2.0")
  endif()
  message(STATUS "Fetching EZMESH ${FETCH_EZMESH_VERSION} from public repository")
endif()

# Find the version of EZMESH
file(
  STRINGS ${EZMESH_SOURCE_DIR}/CMakeLists.txt _ver_line
  REGEX "^ +VERSION \"([^\"]*)\""
  LIMIT_COUNT 1)
string(REGEX MATCHALL "[0-9\.]+" EZMESH_VERSION "${_ver_line}")
message(STATUS "EZMESH version ${EZMESH_VERSION}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  EZMESH
  REQUIRED_VARS EZMESH_VERSION
  VERSION_VAR EZMESH_VERSION)
