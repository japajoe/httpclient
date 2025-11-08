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

#ifndef HTTP_CURL_HPP
#define HTTP_CURL_HPP

#include "curl/curl.h"

namespace http
{
	typedef size_t (*curl_setopt_callback)(void* contents, size_t size, size_t nmemb, void *userp);

	class curl
	{
	public:
		static bool load_library(const char *libraryPath);
		static void close_library();
		static bool is_loaded();
		static CURLcode global_init(long flags);
		static void global_cleanup();
		static CURL *easy_init();
		static void easy_cleanup(CURL *c);
		static CURLcode easy_setopt(CURL *c, CURLoption opt, const char *data);
		static CURLcode easy_setopt(CURL *c, CURLoption opt, curl_setopt_callback data);
		static CURLcode easy_setopt(CURL *c, CURLoption opt, void *data);
		static CURLcode easy_setopt(CURL *c, CURLoption opt, size_t data);
		static CURLcode easy_setopt(CURL *c, CURLoption opt, long data);
		static CURLcode easy_perform(CURL *c);
		static CURLcode easy_getinfo(CURL *c, CURLINFO info, void *data);
		static void slist_free_all(curl_slist *sl);
		static curl_slist *slist_append(curl_slist *sl, const char * str);
		static const char *easy_strerror(CURLcode code);
	private:
		static void *libraryHandle;
	};
}

#endif