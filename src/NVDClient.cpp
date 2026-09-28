#include "cachy-audit/NVDClient.hpp"

#include "cachy-audit/core/consts.hpp"

#include <stdexcept>
#include <thread>

namespace cachy_audit {

json NVDClient::query(std::string_view kernel_version) {
    json vulns = json::array();
    constexpr std::size_t PAGE_SIZE{2000};  // NVD's maximum resultsPerPage
    for (std::size_t start = 0;; start += PAGE_SIZE) {
        const auto url = std::string{internal::NVD_API_BASE} +
                         "?cpeName=" + std::string{internal::NVD_KERNEL_CPE} +
                         std::string{kernel_version} + ":*:*:*:*:*:*:*" +
                         "&resultsPerPage=" + std::to_string(PAGE_SIZE) +
                         "&startIndex=" + std::to_string(start);

        const auto page = fetch_page(url);
        for (const auto& v : page.value("vulnerabilities", json::array()))
            if (const auto it = v.find("cve"); it != v.end()) vulns.push_back(*it);

        if (start + PAGE_SIZE >= static_cast<std::size_t>(page.value("totalResults", 0)))
            break;
    }
    return json{{"vulns", std::move(vulns)}};
}

void NVDClient::pace() {
    using namespace std::chrono;
    constexpr auto WINDOW{30s};
    constexpr std::size_t MAX_REQUESTS{5};

    const auto now = steady_clock::now();
    while (!m_Requests.empty() && now - m_Requests.front() > WINDOW)
        m_Requests.pop_front();
    if (m_Requests.size() >= MAX_REQUESTS)
        std::this_thread::sleep_until(m_Requests.front() + WINDOW);
    m_Requests.push_back(steady_clock::now());
}

json NVDClient::fetch_page(const std::string& url) {
    network::Slist headers{};
    headers.append("User-Agent: " + std::string{internal::USER_AGENT});

    for (int attempt = 0;; ++attempt) {
        pace();
        try {
            std::string post_fields;
            return json::parse(m_Curl.query(url, headers.get(), post_fields));
        } catch (const std::runtime_error& e) {
            // NVD answers excess traffic with 403/429 — wait out the window
            const std::string_view msg{e.what()};
            if ((msg.find("HTTP Error: 403") == std::string_view::npos &&
                 msg.find("HTTP Error: 429") == std::string_view::npos) ||
                attempt >= 2)
                throw;
            std::this_thread::sleep_for(std::chrono::seconds{31});
        }
    }
}

}  // namespace cachy_audit
