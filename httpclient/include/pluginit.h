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

#ifndef PLUGININIT_H
#define PLUGININIT_H

#if defined(PLI_DLL)
    #if defined(_WIN32)
        #define PLI_DLL_IMPORT  __declspec(dllimport)
        #define PLI_DLL_EXPORT  __declspec(dllexport)
        #define PLI_DLL_PRIVATE static
    #else
        #if defined(__GNUC__) && __GNUC__ >= 4
            #define PLI_DLL_IMPORT  __attribute__((visibility("default")))
            #define PLI_DLL_EXPORT  __attribute__((visibility("default")))
            #define PLI_DLL_PRIVATE __attribute__((visibility("hidden")))
        #else
            #define PLI_DLL_IMPORT
            #define PLI_DLL_EXPORT
            #define PLI_DLL_PRIVATE static
        #endif
    #endif
#endif

#if !defined(PLI_API)
    #if defined(PLI_DLL)
        #if defined(PLI_IMPLEMENTATION)
            #define PLI_API  PLI_DLL_EXPORT
        #else
            #define PLI_API  PLI_DLL_IMPORT
        #endif
    #else
        #define PLI_API extern
    #endif
#endif

typedef unsigned char pli_bool;

#define PLI_TRUE 1
#define PLI_FALSE 0

#if defined(__cplusplus)
extern "C" {
#endif

PLI_API void *pli_plugin_load(const char *filePath);
PLI_API void pli_plugin_unload(void *pluginHandle);
PLI_API void *pli_plugin_get_symbol(void *pluginHandle, const char *symbolName);
PLI_API char *pli_find_library_path(const char *libraryName);
PLI_API void pli_free_library_path(char *libraryPath);

#if defined(__cplusplus)
}
#endif

#endif