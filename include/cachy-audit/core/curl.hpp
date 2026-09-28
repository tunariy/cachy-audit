#pragma once

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace cachy_audit::network {

/** @brief RAII wrapper around curl_slist. */
class Slist {
  public:
    Slist() = default;

    ~Slist();

    Slist(const Slist&) = delete;

    Slist& operator=(const Slist&) = delete;

    Slist(Slist&& other) noexcept;

    Slist& operator=(Slist&& other) noexcept;

  public:
    /** @brief Appends a header line; chainable. Throws std::runtime_error on failure. */
    Slist& append(std::string_view header);

    /** @brief Raw list pointer suitable for CURLOPT_HTTPHEADER. */
    [[nodiscard]] curl_slist* get() const noexcept { return m_List; }

  private:
    curl_slist* m_List{};
};

/**
 * @brief RAII wrapper around CURL* designed for NVD and Arch Security Tracker
 */
class Curl {
  public:
    /**
     * @brief Sets defaults: write callback, redirects, and timeouts
     *        (10 s connect, 120 s total) so no request can hang forever.
     *        Throws std::runtime_error if curl_easy_init fails.
     */
    Curl();

    /**
     * @brief GET (or POST when post_fields is non-empty); returns the response body.
     *        Throws std::runtime_error on transport errors or non-2xx status codes.
     */
    [[nodiscard]] std::string query(const std::string& url, curl_slist* headers,
                                    std::string& post_fields);

    /** @brief Raw handle, e.g. for setting additional options. */
    [[nodiscard]] CURL* handle() noexcept { return m_Handle.get(); }

  private:
    /** @brief CURLOPT_WRITEFUNCTION callback; appends to the std::string in userp. */
    static std::size_t write_callback(char* contents, std::size_t size, std::size_t nmemb,
                                      void* userp);

    /** @brief Calls curl_easy_cleanup. */
    struct Deleter {
        void operator()(CURL* p) const noexcept { curl_easy_cleanup(p); }
    };

    std::unique_ptr<CURL, Deleter> m_Handle;
};

}  // namespace cachy_audit::network
