#pragma once

#include "cachy-audit/core/curl.hpp"

#include "nlohmann/json.hpp"

#include <string_view>

namespace cachy_audit {

using json = nlohmann::json;

/** @brief Queries the NVD CVE API for vulnerabilities of the Linux kernel. */
class NVDClient {
  public:
    /**
     * @brief All CVEs NVD lists for a kernel version, as a json object with a
     *        "vulns" array of NVD CVE entries.
     *        Throws std::runtime_error on transport/HTTP errors.
     */
    [[nodiscard]] json query(std::string_view kernel_version);

  private:
    network::Curl m_Curl{};
};

}  // namespace cachy_audit
