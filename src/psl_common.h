/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/**
 * *****************************************************************************
 * @file psl_common.h
 * @ingroup psl_internal 
 * 
 * @brief  Common definitions for libpalmsocket.  This file
 *         should NOT include other libpalmsocket headers
 *         (besides psl_build_config.h)
 * 
 * *****************************************************************************
 */
#ifndef PSL_COMMON_H__
#define PSL_COMMON_H__

#include "psl_build_config.h"



#if defined(__cplusplus)
extern "C" {
#endif


/// Represents an invalid FD (a valid file descriptor is >= 0)
#define PSL_INVALID_FD               (-1)


/**
 * Marks a deliberately unused function parameter (e.g., in uniform
 * state-handler signatures) to suppress -Wunused-parameter
 */
#define PSL_UNUSED(x)                ((void)(x))


/**
 * Casts a function pointer to GSourceFunc for g_source_set_callback()
 * via the generic function-pointer type, avoiding
 * -Wcast-function-type.  (Equivalent to glib 2.58+'s G_SOURCE_FUNC,
 * which older webOS glib versions lack.)
 */
#define PSL_SOURCE_FUNC(f)           ((GSourceFunc)(void (*)(void))(f))


/**
 * Marks an intentional switch-case fallthrough.  (Equivalent to glib
 * 2.60+'s G_GNUC_FALLTHROUGH, which older webOS glib versions lack.)
 */
#if defined(__GNUC__) && __GNUC__ >= 7
    #define PSL_FALLTHROUGH          __attribute__((__fallthrough__))
#else
    #define PSL_FALLTHROUGH          do {} while (0)
#endif



/**
 * @note These are technically output-only conditions from the
 *       posix poll() function family. If a file descriptor
 *       (e.g., socket) is being monitored for any other
 *       condition, and one of these errors occurs, glib will
 *       keep calling us with these flags until the condition is
 *       cleared.  So, even if the user didn't request these
 *       conditions, we'll still be called continuously until
 *       the source of these errors is cleared by the user
 *       (e.g., by closing the watch and the socket).
 */
#define PSL_FAIL_GIOCONDITIONS (G_IO_ERR | G_IO_HUP | G_IO_NVAL)


/**
 * The buffer size we use for logging ASCII domain names; 
 * includes zero-termination 
 */
#define PSL_DOMAIN_NAME_ASCII_LOG_BUF_SIZE    (255 + 1)




#if defined(__cplusplus)
}
#endif

#endif // PSL_COMMON_H__
