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

#include "curl.hpp"
#include "pluginit.h"

namespace http
{
	typedef CURLcode (*curl_global_init_t)(long flags);
	typedef void (*curl_global_cleanup_t)(void);
	typedef CURL *(*curl_easy_init_t)(void);
	typedef void (*curl_easy_cleanup_t)(CURL*);
	typedef CURLcode (*curl_easy_setopt_t)(CURL*, CURLoption, ...);
	typedef CURLcode (*curl_easy_perform_t)(CURL*);
	typedef CURLcode (*curl_easy_getinfo_t)(CURL*, CURLINFO, ...);
	typedef void (*curl_slist_free_all_t)(curl_slist*);
	typedef curl_slist *(*curl_slist_append_t)(curl_slist*, const char*);
	typedef const char *(*curl_easy_strerror_t)(CURLcode);

	curl_global_init_t curl_global_init_ptr = nullptr;
	curl_global_cleanup_t curl_global_cleanup_ptr = nullptr;
	curl_easy_init_t curl_easy_init_ptr = nullptr;
	curl_easy_cleanup_t curl_easy_cleanup_ptr = nullptr;
	curl_easy_setopt_t curl_easy_setopt_ptr = nullptr;
	curl_easy_perform_t curl_easy_perform_ptr = nullptr;
	curl_easy_getinfo_t curl_easy_getinfo_ptr = nullptr;
	curl_slist_free_all_t curl_slist_free_all_ptr = nullptr;
	curl_slist_append_t curl_slist_append_ptr = nullptr;
	curl_easy_strerror_t curl_easy_strerror_ptr = nullptr;

	void *curl::libraryHandle = nullptr;

	static bool is_initialized(void *fn, const char *name)
	{
		if(fn)
			return true;
		
		fprintf(stderr, "Failed to loaded function: %s\n", name);
		curl::close_library();
		return false;
	}

	bool curl::load_library(const char *libraryPath)
	{
		libraryHandle = pli_plugin_load(libraryPath);

		if(!libraryHandle)
			return false;
		
		curl_global_init_ptr = (curl_global_init_t)pli_plugin_get_symbol(libraryHandle, "curl_global_init");
		curl_global_cleanup_ptr = (curl_global_cleanup_t)pli_plugin_get_symbol(libraryHandle, "curl_global_cleanup");
		curl_easy_init_ptr = (curl_easy_init_t)pli_plugin_get_symbol(libraryHandle, "curl_easy_init");
		curl_easy_cleanup_ptr = (curl_easy_cleanup_t)pli_plugin_get_symbol(libraryHandle, "curl_easy_cleanup");
		curl_easy_setopt_ptr = (curl_easy_setopt_t)pli_plugin_get_symbol(libraryHandle, "curl_easy_setopt");
		curl_easy_perform_ptr = (curl_easy_perform_t)pli_plugin_get_symbol(libraryHandle, "curl_easy_perform");
		curl_easy_getinfo_ptr = (curl_easy_getinfo_t)pli_plugin_get_symbol(libraryHandle, "curl_easy_getinfo");
		curl_slist_free_all_ptr = (curl_slist_free_all_t)pli_plugin_get_symbol(libraryHandle, "curl_slist_free_all");
		curl_slist_append_ptr = (curl_slist_append_t)pli_plugin_get_symbol(libraryHandle, "curl_slist_append");
		curl_easy_strerror_ptr = (curl_easy_strerror_t)pli_plugin_get_symbol(libraryHandle, "curl_easy_strerror");

		if(!is_initialized((void*)curl_global_init_ptr, "curl_global_init_ptr"))
			return false;
		if(!is_initialized((void*)curl_global_cleanup_ptr, "curl_global_cleanup_ptr"))
			return false;
		if(!is_initialized((void*)curl_easy_init_ptr, "curl_easy_init_ptr"))
			return false;
		if(!is_initialized((void*)curl_easy_cleanup_ptr, "curl_easy_cleanup_ptr"))
			return false;
		if(!is_initialized((void*)curl_easy_setopt_ptr, "curl_easy_setopt_ptr"))
			return false;
		if(!is_initialized((void*)curl_easy_perform_ptr, "curl_easy_perform_ptr"))
			return false;
		if(!is_initialized((void*)curl_easy_getinfo_ptr, "curl_easy_getinfo_ptr"))
			return false;
		if(!is_initialized((void*)curl_slist_free_all_ptr, "curl_slist_free_all_ptr"))
			return false;
		if(!is_initialized((void*)curl_slist_append_ptr, "curl_slist_append_ptr"))
			return false;
		if(!is_initialized((void*)curl_easy_strerror_ptr, "curl_easy_strerror_ptr"))
			return false;

		return true;
	}

	void curl::close_library()
	{
		if(libraryHandle)
			pli_plugin_unload(libraryHandle);
		libraryHandle = nullptr;
	}

	bool curl::is_loaded()
	{
		return libraryHandle != nullptr;
	}

	CURLcode curl::global_init(long flags)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_global_init_ptr(flags);
	}

	void curl::global_cleanup()
	{
		if(!libraryHandle)
			return;
		curl_global_cleanup_ptr();
	}

	CURL *curl::easy_init()
	{
		if(!libraryHandle)
			return nullptr;
		return curl_easy_init_ptr();
	}

	void curl::easy_cleanup(CURL *c)
	{
		if(!libraryHandle)
			return;
		curl_easy_cleanup_ptr(c);
	}

	CURLcode curl::easy_setopt(CURL *c, CURLoption opt, const char *data)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_setopt_ptr(c, opt, data);
	}

	CURLcode curl::easy_setopt(CURL *c, CURLoption opt, curl_setopt_callback data)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_setopt_ptr(c, opt, data);
	}

	CURLcode curl::easy_setopt(CURL *c, CURLoption opt, void *data)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_setopt_ptr(c, opt, data);
	}

	CURLcode curl::easy_setopt(CURL *c, CURLoption opt, size_t data)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_setopt_ptr(c, opt, data);
	}

	CURLcode curl::easy_setopt(CURL *c, CURLoption opt, long data)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_setopt_ptr(c, opt, data);
	}

	CURLcode curl::easy_perform(CURL *c)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_perform_ptr(c);
	}

	CURLcode curl::easy_getinfo(CURL *c, CURLINFO info, void *data)
	{
		if(!libraryHandle)
			return CURLE_FAILED_INIT;
		return curl_easy_getinfo_ptr(c, info, data);
	}

	void curl::slist_free_all(curl_slist *sl)
	{
		if(!libraryHandle)
			return;
		curl_slist_free_all_ptr(sl);
	}

	curl_slist *curl::slist_append(curl_slist *sl, const char * str)
	{
		if(!libraryHandle)
			return nullptr;
		return curl_slist_append_ptr(sl, str);
	}

	const char *curl::easy_strerror(CURLcode code)
	{
		return curl_easy_strerror_ptr(code);
	}
}