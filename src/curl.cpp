#include "cachy-audit/core/curl.hpp"

#include <stdexcept>
#include <utility>

namespace cachy_audit::network {

Slist::~Slist() { curl_slist_free_all(m_List); }

Slist::Slist(Slist&& other) noexcept : m_List{std::exchange(other.m_List, nullptr)} {}

Slist& Slist::operator=(Slist&& other) noexcept {
    if (this != &other) {
        curl_slist_free_all(m_List);
        m_List = std::exchange(other.m_List, nullptr);
    }
    return *this;
}

Slist& Slist::append(std::string_view header) {
    auto* next = curl_slist_append(m_List, std::string{header}.c_str());
    if (next == nullptr)
        throw std::runtime_error{"Failed to append to curl header list"};
    m_List = next;
    return *this;
}

Curl::Curl() : m_Handle{curl_easy_init()} {
    if (!m_Handle) throw std::runtime_error{"Failed to initialize the curl context!"};

    curl_easy_setopt(handle(), CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(handle(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle(), CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(handle(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(handle(), CURLOPT_TIMEOUT, 120L);
}

std::string Curl::query(const std::string& url, curl_slist* headers,
                        std::string& post_fields) {
    std::string buffer;
    buffer.reserve(10);

    curl_easy_setopt(handle(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle(), CURLOPT_WRITEDATA, &buffer);
    if (!post_fields.empty()) {
        curl_easy_setopt(handle(), CURLOPT_POSTFIELDS, post_fields.data());
        curl_easy_setopt(handle(), CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(post_fields.size()));
    }
    if (headers != nullptr) curl_easy_setopt(handle(), CURLOPT_HTTPHEADER, headers);

    const CURLcode res = curl_easy_perform(handle());
    if (res != CURLE_OK)
        throw std::runtime_error{std::string{"CURL request failed: "} +
                                 curl_easy_strerror(res)};

    long response_code{0l};
    curl_easy_getinfo(handle(), CURLINFO_RESPONSE_CODE, &response_code);
    if (!(300 > response_code && response_code >= 200)) {
        throw std::runtime_error{"HTTP Error: " + std::to_string(response_code) +
                                 "\n" + buffer};
    }

    return buffer;
}

std::size_t Curl::write_callback(char* contents, std::size_t size, std::size_t nmemb,
                                 void* userp) {
    static_cast<std::string*>(userp)->append(contents, size * nmemb);
    return size * nmemb;
}

}  // namespace cachy_audit::network
