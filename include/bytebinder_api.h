/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(BYTEBINDER_BUILD_SHARED)
        #define BYTEBINDER_API __declspec(dllexport)
    #elif defined(BYTEBINDER_USE_SHARED)
        #define BYTEBINDER_API __declspec(dllimport)
    #else
        #define BYTEBINDER_API
    #endif
#else
    #if defined(BYTEBINDER_BUILD_SHARED) || defined(BYTEBINDER_USE_SHARED)
        #define BYTEBINDER_API __attribute__((visibility("default")))
    #else
        #define BYTEBINDER_API
    #endif
#endif
