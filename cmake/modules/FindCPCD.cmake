# Find the Silicon Labs CPCd location
# =============================================================================
# Usage of this module is as follows:
#
# find_package(CPCD)
#
# cmake-format: off
# Variables used by this module:
#
# Variables defined by this module:
# * CPCD_FOUND - True if the CPCd sources are found.
# cmake-format: on
# =============================================================================
if(CPCD_LOCATION)
  set(FETCHCONTENT_SOURCE_DIR_CPCD CMAKE_SOURCE_DIR "${CPCD_LOCATION}")
  message(STATUS "Found CPCd at ${CPCD_LOCATION}")
elseif(DEFINED ENV{CPCD_LOCATION})
    set(FETCHCONTENT_SOURCE_DIR_CPCD "$ENV{CPCD_LOCATION}")
    message(STATUS "CPCd - using provided CPCD_LOCATION ($ENV{CPCD_LOCATION})")
else()
  if(NOT FETCH_CPCD_VERSION)
    # The version to fetch should ideally be the same as the version used for fetching GeckoSDK
    set(FETCH_CPCD_VERSION "v4.2.0")
  endif()
  message(STATUS "Fetching CPCd ${FETCH_CPCD_VERSION} from public repository")
endif()

# Find the version of CPCd
file(
  STRINGS ${cpcd_SOURCE_DIR}/CMakeLists.txt _ver_line
  REGEX "^ +VERSION \"([^\"]*)\""
  LIMIT_COUNT 1)
string(REGEX MATCHALL "[0-9\.]+" CPCD_VERSION "${_ver_line}")
message(STATUS "CPCd version  ${CPCD_VERSION}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  CPCD
  REQUIRED_VARS CPCD_VERSION
  VERSION_VAR CPCD_VERSION)
