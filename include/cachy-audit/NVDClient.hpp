#pragma once

#include "cachy-audit/core/curl.hpp"

#include "nlohmann/json.hpp"

#include <chrono>
#include <deque>
#include <string>
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
    /** @brief NVD allows 5 requests per 30 s without an API key; sleeps when the window is full. */
    void pace();

    /** @brief GETs one page; waits out NVD's rate-limit response and retries. */
    [[nodiscard]] json fetch_page(const std::string& url);

    network::Curl m_Curl{};
    std::deque<std::chrono::steady_clock::time_point> m_Requests{};
};

}  // namespace cachy_audit
