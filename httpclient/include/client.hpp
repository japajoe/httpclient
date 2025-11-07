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

	class client
	{
	public:
		client();
		~client();
		bool get(const std::string &url, const headers *requestHeaders, int &statusCode, std::string &response);
        bool post(const std::string &url, const headers *requestHeaders, const void *data, size_t size, const std::string &contentType, int &statusCode, std::string &response);
	private:
        bool get_from_socket(const std::string &url, const headers *requestHeaders, int &statusCode, std::string &response);
        bool get_from_curl(const std::string &url, const headers *requestHeaders, int &statusCode, std::string &response);
        bool post_from_socket(const std::string &url, const headers *requestHeaders, const void *data, size_t size, const std::string &contentType, int &statusCode, std::string &response);
        bool post_from_curl(const std::string &url, const headers *requestHeaders, const void *data, size_t size, const std::string &contentType, int &statusCode, std::string &response);
        bool connect(socket_t *s, const std::string &url, std::string &path, std::string &hostName);
		void close(socket_t *s);
		int64_t read(socket_t *s, void *buffer, size_t size);
		int64_t peek(socket_t *s, void *buffer, size_t size);
		int64_t write(socket_t *s, const void *buffer, size_t size);
        bool write_all_bytes(socket_t *s, const void *buffer, size_t size);
	};
}

#endif