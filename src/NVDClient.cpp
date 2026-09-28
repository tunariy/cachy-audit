#include "cachy-audit/NVDClient.hpp"

#include "cachy-audit/core/consts.hpp"

#include <string>

namespace cachy_audit {

json NVDClient::query(std::string_view kernel_version) {
    network::Slist headers{};
    headers.append("User-Agent: " + std::string{internal::USER_AGENT});

    json vulns = json::array();
    constexpr std::size_t PAGE_SIZE{2000};  // NVD's maximum resultsPerPage
    for (std::size_t start = 0;; start += PAGE_SIZE) {
        const auto url = std::string{internal::NVD_API_BASE} + "?cpeName=" +
                         std::string{internal::NVD_KERNEL_CPE} +
                         std::string{kernel_version} + ":*:*:*:*:*:*:*" +
                         "&resultsPerPage=" + std::to_string(PAGE_SIZE) +
                         "&startIndex=" + std::to_string(start);

        std::string post_fields;
        const auto page = json::parse(m_Curl.query(url, headers.get(), post_fields));
        for (const auto& v : page.value("vulnerabilities", json::array()))
            if (const auto it = v.find("cve"); it != v.end()) vulns.push_back(*it);

        if (start + PAGE_SIZE >=
            static_cast<std::size_t>(page.value("totalResults", 0)))
            break;
    }
    return json{{"vulns", std::move(vulns)}};
}

}  // namespace cachy_audit
