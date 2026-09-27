/**
 * @file curl.hpp
 * @brief Thin RAII wrappers around libcurl: header lists and an easy handle.
 */

#pragma once

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace cachy_audit::network {

/** @brief RAII wrapper around curl_slist. */
class Slist {
  public:
    Slist() = default;

    ~Slist() { curl_slist_free_all(m_List); }

    Slist(const Slist&) = delete;

    Slist& operator=(const Slist&) = delete;

    Slist(Slist&& other) noexcept : m_List{std::exchange(other.m_List, nullptr)} {}

    Slist& operator=(Slist&& other) noexcept {
        if (this != &other) {
            curl_slist_free_all(m_List);
            m_List = std::exchange(other.m_List, nullptr);
        }
        return *this;
    }

  public:
    /** @brief Appends a header line; chainable. Throws std::runtime_error on failure. */
    Slist& append(std::string_view header) {
        auto* next = curl_slist_append(m_List, std::string{header}.c_str());
        if (next == nullptr)
            throw std::runtime_error{"Failed to append to curl header list"};
        m_List = next;
        return *this;
    }

    /** @brief Raw list pointer suitable for CURLOPT_HTTPHEADER. */
    [[nodiscard]] curl_slist* get() const noexcept { return m_List; }

  private:
    curl_slist* m_List{};
};

/**
 * @brief RAII wrapper around CURL* designed for api.osv and Arch Security Tracker
 */
class Curl {
  public:
    /**
     * @brief Sets defaults: write callback, redirects, and timeouts
     *        (10 s connect, 120 s total) so no request can hang forever.
     *        Throws std::runtime_error if curl_easy_init fails.
     */
    Curl() : m_Handle{curl_easy_init()} {
        if (!m_Handle) throw std::runtime_error{"Failed to initialize the curl context!"};

        curl_easy_setopt(handle(), CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(handle(), CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(handle(), CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(handle(), CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(handle(), CURLOPT_TIMEOUT, 120L);
    }

    /**
     * @brief GET (or POST when post_fields is non-empty); returns the response body.
     *        Throws std::runtime_error on transport errors or non-2xx status codes.
     */
    [[nodiscard]] std::string query(const std::string& url, curl_slist* headers,
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

    /** @brief Raw handle, e.g. for setting additional options. */
    [[nodiscard]] CURL* handle() noexcept { return m_Handle.get(); }

  private:
    /** @brief CURLOPT_WRITEFUNCTION callback; appends to the std::string in userp. */
    static std::size_t write_callback(char* contents, std::size_t size, std::size_t nmemb,
                                      void* userp) {
        static_cast<std::string*>(userp)->append(contents, size * nmemb);
        return size * nmemb;
    }

    /** @brief Calls curl_easy_cleanup. */
    struct Deleter {
        void operator()(CURL* p) const noexcept { curl_easy_cleanup(p); }
    };

    std::unique_ptr<CURL, Deleter> m_Handle;
};

}  // namespace cachy_audit::network
