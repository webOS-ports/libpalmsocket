/* @@@LICENSE
*
*      Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
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

/** ****************************************************************************
 * @file psl_openssl_compat.h
 * @ingroup psl_internal
 *
 * @brief  OpenSSL version-compatibility shims.
 *
 * libpalmsocket builds against OpenSSL 0.9.8 (legacy webOS devices),
 * 1.0.x, 1.1.x, and 3.x.  The implementation code uses the modern
 * (OpenSSL 1.1+) API names; this header maps them onto the legacy API
 * when building against older OpenSSL.
 *
 * *****************************************************************************
 */
#ifndef PSL_OPENSSL_COMPAT_H__
#define PSL_OPENSSL_COMPAT_H__

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#if defined(__cplusplus)
extern "C" {
#endif


#if OPENSSL_VERSION_NUMBER < 0x10100000L

/// ASN1_STRING_get0_data() replaced ASN1_STRING_data() in 1.1.0
#define ASN1_STRING_get0_data(s)        ASN1_STRING_data(s)

/// TLS_method() replaced SSLv23_method() in 1.1.0
#define TLS_method()                    SSLv23_method()

/// X509_OBJECT accessors (the struct became opaque in 1.1.0)
/// @note macro parameter names deliberately avoid the member names
///       to prevent parameter capture during expansion
#define X509_OBJECT_get_type(xobj_)     ((xobj_)->type)

static inline X509*
X509_OBJECT_get0_X509(const X509_OBJECT* const obj)
{
    return (obj && X509_LU_X509 == obj->type) ? obj->data.x509 : NULL;
}

static inline X509_OBJECT*
X509_OBJECT_new(void)
{
    X509_OBJECT* const obj = OPENSSL_malloc(sizeof(*obj));
    if (obj) {
        memset(obj, 0, sizeof(*obj));
    }
    return obj;
}

static inline void
X509_OBJECT_free(X509_OBJECT* const obj)
{
    if (obj) {
        X509_OBJECT_free_contents(obj);
        OPENSSL_free(obj);
    }
}

/// X509_STORE/X509_STORE_CTX accessors (opaque since 1.1.0)
#define X509_STORE_CTX_get0_store(xsc_) ((xsc_)->ctx)
#define X509_STORE_get0_objects(xst_)   ((xst_)->objs)

/**
 * OPENSSL_thread_stop() is the 1.1.0+ replacement for the legacy
 * per-thread error-state cleanup
 */
#if OPENSSL_VERSION_NUMBER < 0x10000000L
    #define OPENSSL_thread_stop()       ERR_remove_state(0)
#else
    #define OPENSSL_thread_stop()       ERR_remove_thread_state(NULL)
#endif

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L


#if defined(__cplusplus)
}
#endif

#endif // PSL_OPENSSL_COMPAT_H__
