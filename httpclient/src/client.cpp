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

#include "client.hpp"
#include "curl.hpp"
#include "pluginit.h"
#include <vector>
#include <regex>
#include <sstream>
#include <cstring>
#include <iostream>
#include <iomanip> // for std::hex and std::setw
#include <atomic>

namespace http
{
    static std::atomic<int> gCount = 0;

    static void write_error(const std::string &message) 
	{
		std::cout << message << '\n';
    }

    static bool string_contains(const std::string &haystack, const std::string &needle) 
	{
        return haystack.find(needle) != std::string::npos;
    }

    static bool string_ends_with(const std::string &haystack, const std::string &needle) 
	{
        if (haystack.length() >= needle.length()) 
            return (0 == haystack.compare(haystack.length() - needle.length(), needle.length(), needle));
        return false;
    }

    static std::string string_trim_start(const std::string& str) 
    {
        size_t start = 0;

        // Find the first non-whitespace character
        while (start < str.length() && std::isspace(static_cast<unsigned char>(str[start]))) 
        {
            ++start;
        }

        // Return the substring from the first non-whitespace character to the end
        return str.substr(start);
    }

    static std::vector<std::string> string_split(const std::string& str, char separator, size_t max_parts = 0) 
    {
        std::vector<std::string> result;
        size_t start = 0;
        size_t end = 0;

        while ((end = str.find(separator, start)) != std::string::npos) {
            result.push_back(str.substr(start, end - start));
            start = end + 1;

            if (max_parts > 0 && result.size() >= max_parts - 1) {
                break; // Stop if we have reached maximum parts
            }
        }
        result.push_back(str.substr(start)); // Add the last part
        return result;
    }
    
	static bool try_parse_uint16(const std::string &value, uint16_t &v)
	{
        std::stringstream ss(value);
        ss >> v;

        if (ss.fail() || !ss.eof())
            return false;
        
        return true;
	}

    static bool try_parse_int32(const std::string &value, int32_t &v)
    {
        std::stringstream ss(value);
        ss >> v;

        if (ss.fail() || !ss.eof())
            return false;
        
        return true;
    }

    static bool uri_get_scheme(const std::string &uri, std::string &value) 
	{
        std::regex schemeRegex(R"(([^:/?#]+):\/\/)");
        std::smatch match;
        if (std::regex_search(uri, match, schemeRegex)) 
		{
            value = match[1];
            return true;
        }
        return false;
    }

    static bool uri_get_host(const std::string &uri, std::string &value) 
	{
        std::regex hostRegex(R"(:\/\/([^/?#]+))");
        std::smatch match;
        if (std::regex_search(uri, match, hostRegex)) 
		{
            value = match[1];
            return true;
        }
        return false;
    }


    static bool uri_get_path(const std::string &uri, std::string &value) 
	{
        std::regex pathRegex(R"(:\/\/[^/?#]+([^?#]*))");
        std::smatch match;
        if (std::regex_search(uri, match, pathRegex)) 
		{
            value = match[1];
            return true;
        }
        return false;
    }

    static bool is_valid_ip(const std::string& str) 
    {
        std::regex ipv4_pattern(
            R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
        std::regex ipv6_pattern(
            R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");

        return std::regex_match(str, ipv4_pattern) || std::regex_match(str, ipv6_pattern);
    }

    static bool resolve(const std::string &uri, std::string &ip, uint16_t &port, std::string &hostname) 
	{
        std::string scheme, host, path;

        if(!uri_get_scheme(uri, scheme)) 
		{
            write_error("Failed to get scheme from URI");
            return false;
        }

        if(!uri_get_host(uri, host)) 
		{
            write_error("Failed to get host from URI");
            return false;
        }


        if(!uri_get_path(uri, path)) 
		{
            write_error("Failed to get path from URI");
            return false;
        }        

        if(string_contains(host, ":")) 
		{
            auto parts = string_split(host, ':');

            if(parts.size() != 2)
                return false;
            
            //Get rid of the :port part in the host
            host = parts[0];

            if(!try_parse_uint16(parts[1], port))
                return false;
            
        } 
		else 
		{
            if(scheme == "https")
                port = 443;
            else if(scheme == "http") 
                port = 80;
			else 
                return false;
        }

        // Resolve the hostname to an IP address
        struct addrinfo hints, *res;
        std::memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP

        int status = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);

        if (status != 0) 
		{
			std::string error = "getaddrinfo error: " + std::string(gai_strerror(status));
            write_error(error);
            return false;
        }

        hostname = host;

        for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) 
		{
            void* addr;

            // Get the pointer to the address itself
            if (p->ai_family == AF_INET) 
			{ // IPv4
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } 
			else 
			{ // IPv6
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }

            // Convert the IP to a string
            char ipstr[INET6_ADDRSTRLEN];
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            ip = ipstr;
        }

        freeaddrinfo(res);
        return true;
    }

    static ip_version detect_ip_version(const std::string &ip) 
	{
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;

        if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) 
            return ip_version_ip_v4;

        if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1)
            return ip_version_ip_v6;

        return ip_version_invalid;
    }

	client::client()
	{
    #ifdef _WIN32
        if(gCount.load() == 0)
        {
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
            {
                write_error("Failed to initialize winsock");
            }
        }
    #endif

        if(gCount.load() == 0)
        {
        #ifdef _WIN32
            const char *curlPath = "curl.dll";
        #else
            char *curlPath = pli_find_library_path("libcurl.so");            
        #endif
            if(curlPath)
            {
                if(curl::load_library(curlPath))
                {
                    curl::global_init(CURL_GLOBAL_DEFAULT);
                }
            #ifndef _WIN32
                pli_free_library_path(curlPath);
            #endif
            }
        }

        gCount.store(gCount.load() + 1);
	}

	client::~client()
	{
    #ifdef _WIN32
        if(gCount.load() == 1)
        {
            WSACleanup();
        }
    #endif

        if(gCount.load() == 1)
        {
            curl::global_cleanup();
            curl::close_library();
        }
        
        gCount.store(gCount.load() - 1);
	}

	bool client::get(const request &req, response &res)
	{
        if(curl::is_loaded())
            return get_from_curl(req, res);
        else
            return get_from_socket(req, res);
	}

    bool client::post(const request &req, const std::string &contentType, response &res)
    {
        if(curl::is_loaded())
            return post_from_curl(req, contentType, res);
        else
            return post_from_socket(req, contentType, res);
    }
    
    bool client::get_from_socket(const request &req, response &res)
    {
		socket_t s = {0};
        std::string path;
        std::string hostName;

        if(!connect(&s, req.get_url(), path, hostName))
            return false;

		std::string request;

    	request += "GET " + path + " HTTP/1.1\r\n";
    	request += "Host: " + hostName + "\r\n";
    	request += "Accept: */*\r\n";

        auto requestHeaders = req.get_headers();

		if(requestHeaders.size() > 0)
		{
			for(const auto &h : requestHeaders)
			{
				request += h.first + ": " + h.second + "\r\n";
			}
		}

    	request += "Connection: close\r\n\r\n";

        // Send the header
        if(!write_all_bytes(&s, request.data(), request.size()))
        {
            close(&s);
            return false;
        }

		int64_t bytesReceived = 0;
		unsigned char buffer[1024];
		std::memset(buffer, 0, 1024);
        std::string response;

		while ((bytesReceived = read(&s, buffer, 1023)) > 0) 
		{
			response.append((char*)buffer, bytesReceived);
		}

		close(&s);

        if(!parse_header(response, res.header, res.statusCode))
            return false;

        if(response.size() > 0)
        {
            res.content.resize(response.size());
            std::memcpy(res.content.data(), response.data(), response.size());
        }

		return true;
    }

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) 
    {
        size_t totalSize = size * nmemb;
        std::string* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }

    static size_t HeaderCallback(void* contents, size_t size, size_t nmemb, void *userp) 
    {
        size_t totalSize = size * nmemb;
        std::string* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), totalSize);
        return totalSize;
    }

    bool client::get_from_curl(const request &req, response &res)
    {
        CURL *gCurl = curl::easy_init();
        if (!gCurl) return false;

        std::string requestHeader;
        std::string response;

        curl::easy_setopt(gCurl, CURLOPT_URL, req.get_url().c_str());
        curl::easy_setopt(gCurl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl::easy_setopt(gCurl, CURLOPT_WRITEDATA, &response);
        curl::easy_setopt(gCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl::easy_setopt(gCurl, CURLOPT_HEADERDATA, &requestHeader);

		struct curl_slist* requestHeaderList = nullptr;

        auto requestHeaders = req.get_headers();

		if(requestHeaders.size() > 0)
		{
			for(const auto &h : requestHeaders)
			{
				std::string s = h.first + ": " + h.second;
				requestHeaderList = curl::slist_append(requestHeaderList, s.c_str());
			}
			
			curl::easy_setopt(gCurl, CURLOPT_HTTPHEADER, requestHeaderList);
		}

        CURLcode result = curl::easy_perform(gCurl);

        if (result != CURLE_OK) 
        {
			std::string error = "GET request failed: " + std::string(curl::easy_strerror(result));
            write_error(error);
			if(requestHeaderList)
				curl::slist_free_all(requestHeaderList);
            curl::easy_cleanup(gCurl);
            return false;
        }

		if(requestHeaderList)
			curl::slist_free_all(requestHeaderList);

        if(!parse_header(requestHeader, res.header, res.statusCode))
        {
            write_error("Failed to parse header");
            curl::easy_cleanup(gCurl);
            return false;
        }

        if(response.size() > 0)
        {
            res.content.resize(response.size());
            std::memcpy(res.content.data(), response.data(), response.size());
        }
        
        curl::easy_cleanup(gCurl);

        return true;
    }

    bool client::post_from_socket(const request &req, const std::string &contentType, response &res)
    {
        if(req.get_content() == nullptr || req.get_content_length() == 0)
            return false;

		socket_t s = {0};
        std::string path;
        std::string hostName;

        if(!connect(&s, req.get_url(), path, hostName))
            return false;

        if(string_ends_with(path, "/"))
            path.pop_back();

		std::string request;

        request += "POST " + path + " HTTP/1.1\r\n";
        request += "Host: " + hostName + "\r\n";
        request += "Accept: */*\r\n";

        auto requestHeaders = req.get_headers();

		if(requestHeaders.size() > 0)
		{
			for(const auto &h : requestHeaders)
			{
				request += h.first + ": " + h.second + "\r\n";
			}
		}

		request += "Content-Type: " + contentType + "\r\n";
        request += "Content-Length: " + std::to_string(req.get_content_length()) + "\r\n";
        request += "Connection: close\r\n\r\n";

        // Send the header
        if(!write_all_bytes(&s, request.data(), request.size()))
        {
            close(&s);
            return false;
        }

        // Send the content
        if(!write_all_bytes(&s, req.get_content(), req.get_content_length()))
        {
            close(&s);
            return false;
        }

        int64_t bytesReceived = 0;
        uint8_t buffer[1024];
        std::memset(buffer, 0, 1024);
        std::string response;

		while ((bytesReceived = read(&s, buffer, 1023)) > 0) 
		{
			response.append((char*)buffer, bytesReceived);
		}

		close(&s);

        if(!parse_header(response, res.header, res.statusCode))
            return false;

        if(response.size() > 0)
        {
            res.content.resize(response.size());
            std::memcpy(res.content.data(), response.data(), response.size());
        }

		return true;
    }

    bool client::post_from_curl(const request &req, const std::string &contentType, response &res)
    {
        CURL *gCurl = curl::easy_init();
        if (!gCurl) return false;

        std::string responseHeader;
        std::string response;

        curl::easy_setopt(gCurl, CURLOPT_URL, req.get_url().c_str());
        curl::easy_setopt(gCurl, CURLOPT_POSTFIELDS, (void*)req.get_content());
        curl::easy_setopt(gCurl, CURLOPT_POSTFIELDSIZE, req.get_content_length());
        curl::easy_setopt(gCurl, CURLOPT_WRITEFUNCTION, (void*)WriteCallback);
        curl::easy_setopt(gCurl, CURLOPT_WRITEDATA, &response);
        curl::easy_setopt(gCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl::easy_setopt(gCurl, CURLOPT_HEADERDATA, &responseHeader);

        std::string cType = "Content-Type: " + contentType;
        struct curl_slist* requestHeaderList = nullptr;
        requestHeaderList = curl::slist_append(requestHeaderList, cType.c_str());

        auto requestHeaders = req.get_headers();

		if(requestHeaders.size())
		{
			for(const auto &h : requestHeaders)
			{
				std::string s = h.first + ": " + h.second;
				requestHeaderList = curl::slist_append(requestHeaderList, s.c_str());
			}
		}

        curl::easy_setopt(gCurl, CURLOPT_HTTPHEADER, requestHeaderList);

        CURLcode result = curl::easy_perform(gCurl);

        if (result != CURLE_OK) 
        {
			std::string error = "POST request failed: " + std::string(curl::easy_strerror(result));
			write_error(error);
            curl::slist_free_all(requestHeaderList);
            curl::easy_cleanup(gCurl);
            return false;
        }

        curl::slist_free_all(requestHeaderList);

        if(!parse_header(responseHeader, res.header, res.statusCode))
        {
            curl::easy_cleanup(gCurl);
            return false;
        }

        if(response.size() > 0)
        {
            res.content.resize(response.size());
            std::memcpy(res.content.data(), response.data(), response.size());
        }

        curl::easy_cleanup(gCurl);

        return true;
    }

    bool client::connect(socket_t *s, const std::string &url, std::string &path, std::string &hostName)
    {
        std::string URL = url;

        if(!string_ends_with(URL, "/"))
            URL += "/";

        std::string scheme;

        if(!uri_get_scheme(URL, scheme)) 
		{
            write_error("client::get_string: failed to determine scheme from URI " + URL);
            return false;
        }

        if(!uri_get_path(URL, path)) 
		{
            write_error("client::get_string: failed to determine path from URI " + URL);
            return false;
        }

        std::string ip;
        uint16_t port;
        
        if(!resolve(URL, ip, port, hostName)) 
        {
            write_error("client::get_string: failed to resolve IP from URI " + URL);
            return false;
        }

        ip_version ipVersion = detect_ip_version(ip);

        if(ipVersion == ip_version_invalid) 
		{
            write_error("client::get_string: invalid IP version");
            return false;
        }
        
        address_family addressFamily = (ipVersion == ip_version_ip_v4) ? address_family_af_inet : address_family_af_inet6;

        s->fd = socket(static_cast<int>(addressFamily), SOCK_STREAM, 0);

        if(s->fd < 0) 
		{
            write_error("client::get_string: failed to create socket");
            return false;
        }

        int connectionResult = 0;

        s->addressFamily = addressFamily;

        if(ipVersion == ip_version_ip_v4) 
		{
            s->address.ipv4.sin_family = AF_INET;
            s->address.ipv4.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &s->address.ipv4.sin_addr);
            connectionResult = ::connect(s->fd, (struct sockaddr*)&s->address.ipv4, sizeof(s->address.ipv4));
        } 
		else 
		{
            s->address.ipv6.sin6_family = AF_INET6;
            s->address.ipv6.sin6_port = htons(port);
            inet_pton(AF_INET6, ip.c_str(), &s->address.ipv6.sin6_addr);
            connectionResult = ::connect(s->fd, (struct sockaddr*)&s->address.ipv6, sizeof(s->address.ipv6));
        }

        if(connectionResult < 0) 
		{
            write_error("client::get_string: failed to connect");
            close(s);
            return false;
        }

        return true;
    }

	void client::close(socket_t *s)
	{
        if(s->fd >= 0) 
		{
            auto emptyBuffers = [&] () {
                uint8_t buffer[1024];
                while(true) {
                    int64_t n = read(s, buffer, 1024);
                    if(n <= 0)
                        break;
                }
            };

        #ifdef _WIN32
            ::shutdown(s->fd, SD_SEND);
            emptyBuffers();
            closesocket(s->fd);
        #else
            ::shutdown(s->fd, SHUT_WR);
            emptyBuffers();
            ::close(s->fd);
        #endif
            s->fd = -1;
        }
	}

    int64_t client::read(socket_t *s, void *buffer, size_t size) 
	{
        int64_t n = 0;
    #ifdef _WIN32
            n = ::recv(s->fd, (char*)buffer, size, 0);
    #else
            n = ::recv(s->fd, buffer, size, 0);
    #endif
        return n;
    }

    int64_t client::peek(socket_t *s, void *buffer, size_t size) 
	{
    #ifdef _WIN32
        return ::recv(s->fd, (char*)buffer, size, MSG_PEEK);
    #else
        return ::recv(s->fd, buffer, size, MSG_PEEK);
    #endif
    }

    int64_t client::write(socket_t *s, const void *buffer, size_t size)
	{
        int64_t n = 0;
    #ifdef _WIN32
            n = ::send(s->fd, (char*)buffer, size, 0);
    #else
            n = ::send(s->fd, buffer, size, 0);
    #endif
        return n;
    }

    bool client::write_all_bytes(socket_t *s, const void *buffer, size_t size)
    {
        const uint8_t *ptr = static_cast<const uint8_t*>(buffer);
        size_t totalSent = 0;

        while (totalSent < size) 
        {
            int64_t bytesSent = write(s, ptr + totalSent, size - totalSent);
            
            if (bytesSent < 0) 
            {
                // An error occurred
                return false;
            } 
            else if (bytesSent == 0) 
            {
                // Connection closed
                return false;
            }

            totalSent += bytesSent;
        }

        return true; // All bytes sent successfully
    }

    bool client::parse_header(const std::string &responseText, headers &header, int &statusCode)
    {
        std::istringstream responseStream(responseText);
        std::string line;
        size_t count = 0;

        while(std::getline(responseStream, line))
        {
            line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

            if(line.size() == 0)
                continue;

            if(count == 0)
            {
                if(line[line.size() - 1] == ' ')
                    line.pop_back();

                auto parts = string_split(line, ' ', 0);
                
                if(parts.size() < 2)
                    return false;

                if(!try_parse_int32(parts[1], statusCode))
                    return false;
            }
            else
            {
                auto fields = string_split(line, ':', 2);

                if(fields.size() == 2)
                {
                    fields[1] = string_trim_start(fields[1]);
                    header[fields[0]] = fields[1];
                }
            }

            count++;
        }

        return count > 0;
    }

    request::request()
    {
        content = nullptr;
        contentLength = 0;
        ownsData = false;
    }

    request::~request()
    {
        if(content && ownsData)
        {
            delete[] content;
        }
    }

    request &request::set_url(const std::string &url)
    {
        this->url = url;
        return *this;
    }

    std::string request::get_url() const
    {   
        return url;
    }

    void request::set_content(void *data, size_t size, bool copyData)
    {
        if(!data || size == 0)
            return;

        if(content && ownsData)
        {
            delete[] content;
            content = nullptr;
            contentLength = 0;
        }

        ownsData = copyData;
        contentLength = size;

        if(ownsData)
        {
            content = new uint8_t[size];
            std::memcpy(content, data, size);
        }
        else
        {
            content = reinterpret_cast<uint8_t*>(data);
            contentLength = size;
        }

        return;
    }

    uint8_t *request::get_content() const
    {
        return content;
    }

    uint64_t request::get_content_length() const
    {
        return contentLength;
    }

    void request::set_header(const std::string &key, const std::string &value)
    {
        header[key] = value;
    }

    headers request::get_headers() const
    {
        return header;
    }

    response::response()
    {
        statusCode = 0;
    }

    int response::get_status_code() const
    {
        return statusCode;
    }
    
    std::vector<uint8_t> &response::get_content()
    {
        return content;
    }

    std::string response::get_content_as_string() const
    {
        if(content.size() == 0)
            return 0;
        
        std::string res((char*)content.data(), content.size());
        return res;
    }

    uint64_t response::get_content_length() const
    {
        return content.size();
    }

    headers &response::get_headers()
    {
        return header;
    }
}