# ./src
include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

add_library(Cachy_Audit
    audit.cpp
    ASTClient.cpp
    CveQuerier.cpp
    Cvss.cpp
    curl.cpp
    NVDClient.cpp
    Reporter.cpp
    system.cpp
    vercmp.cpp
)

target_include_directories(Cachy_Audit
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

target_compile_features(Cachy_Audit PUBLIC cxx_std_20)
target_link_libraries(Cachy_Audit PUBLIC nlohmann_json::nlohmann_json CURL::libcurl)

add_executable(cachy-audit main.cpp)

target_link_libraries(cachy-audit PRIVATE Cachy_Audit CURL::libcurl)

target_compile_features(cachy-audit PRIVATE cxx_std_20)