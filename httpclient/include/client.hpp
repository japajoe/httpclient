// MIT License

// Copyright (c) 2025 W.M.R Jap-A-Joe

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


#ifndef HTTP_CLIENT_HPP
#define HTTP_CLIENT_HPP

#ifdef _WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include <string>
#include <cstdint>
#include <cstdlib>
#include <unordered_map>
#include <vector>
#include <functional>

namespace http
{
    enum address_family 
	{
        address_family_af_inet = AF_INET,
        address_family_af_inet6 = AF_INET6
    };

    enum ip_version
	{
        ip_version_ip_v4,
        ip_version_ip_v6,
        ip_version_invalid
    };

    typedef struct sockaddr_in sockaddr_in_t;
    typedef struct sockaddr_in6 sockaddr_in6_t;

    typedef union 
	{
        sockaddr_in_t ipv4;
        sockaddr_in6_t ipv6;
    } socket_address_t;

    typedef struct 
	{
        int32_t fd;
        socket_address_t address;
        address_family addressFamily;
    } socket_t;

	using headers = std::unordered_map<std::string,std::string>;

    class request
    {
    public:
        request();
        ~request();
        void set_url(const std::string &url);
        std::string get_url() const;
        void set_content(void *data, size_t size, bool copyData = false);
        uint8_t *get_content() const;
        size_t get_content_length() const;
        void set_content_type(const std::string &contentType);
        std::string get_content_type() const;
        void set_header(const std::string &key, const std::string &value);
        headers get_headers() const;
    private:
        std::string url;
        uint8_t *content;        
        size_t contentLength;
        std::string contentType;
        headers header;
        bool ownsData;
    };
    
    class client;

    class response
    {
    friend class client;
    public:
        response();
        int get_status_code() const;
        size_t get_content_length() const;
        headers &get_headers();
    private:
        int32_t statusCode;
        size_t contentLength;
        headers header;
    };

    enum header_error 
    {
        header_error_none,
        header_error_failed_to_peek,
        header_error_failed_to_read,
        header_error_end_not_found,
        header_error_max_size_exceeded
    };

    using response_callback = std::function<void(const void *data,size_t size)>;

	class client
	{
	public:
        response_callback onResponse;
		client(bool useCurl = true);
		~client();
		bool get(const request &req, response &res);
        bool post(const request &req, response &res);
        void set_use_curl(bool use);
        bool use_curl() const;
        void set_validate_certificate(bool validate);
        bool validate_certificate() const;
	private:
        bool useCurl;
        bool validateCertificate;
        bool get_from_socket(const request &req, response &res);
        bool get_from_curl(const request &req, response &res);
        bool post_from_socket(const request &req, response &res);
        bool post_from_curl(const request &req, response &res);
        static bool connect(socket_t *s, const std::string &url, std::string &path, std::string &hostName);
		static void close(socket_t *s);
		static int64_t read(socket_t *s, void *buffer, size_t size);
		static int64_t peek(socket_t *s, void *buffer, size_t size);
		static int64_t write(socket_t *s, const void *buffer, size_t size);
        static bool write_all_bytes(socket_t *s, const void *buffer, size_t size);
        static header_error read_header(socket_t *s, std::string &header);
        static bool parse_header(const std::string &responseText, headers &header, int &statusCode, uint64_t &contentLength);
        static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);
        static size_t header_callback(void* contents, size_t size, size_t nmemb, void* userp);
	};
}

#endif