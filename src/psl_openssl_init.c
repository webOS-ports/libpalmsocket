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

/** ****************************************************************************
 * @file psl_openssl_init.c
 * @ingroup psl_internal
 *
 * @brief  Openssl library initialization and uninitialization
 *         implementation.
 *
 * @note This module supports OpenSSL 0.9.8 through 3.x.  With
 *       OpenSSL 1.1.0 and later the library initializes itself on
 *       first use, is internally thread-safe (the legacy
 *       CRYPTO_set_locking_callback machinery was removed upstream),
 *       and performs its own cleanup via atexit(); on those versions
 *       only the reference-counted bookkeeping, error-string loading
 *       and PRNG seeding remain active here.  When building against
 *       OpenSSL 0.9.8/1.0.x, the historical explicit init/cleanup and
 *       thread-safety locking hooks are compiled in (see
 *       PSL_OPENSSL_LEGACY_INIT below).
 *
 * *****************************************************************************
 */
#include "psl_build_config.h"

#include <stdbool.h>
#include <stdlib.h>

#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    #define PSL_OPENSSL_LEGACY_INIT 1
    #include <openssl/conf.h>
    #include <openssl/engine.h>
#else
    #define PSL_OPENSSL_LEGACY_INIT 0
#endif

#include "psl_openssl_compat.h"

/**
 * openssl thread support test per 'man
 * CRYPTO_set_locking_callback'
 */
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(OPENSSL_THREADS)
    // thread support enabled
#else
    // no thread support
    #error "ERROR: openssl thread support is disabled"
#endif

#include "palmsocket.h"

#include "psl_log.h"
#include "psl_assert.h"

#include "psl_refcount.h"


#if PSL_OPENSSL_LEGACY_INIT
/**
 * Structures for our openssl thread-safety hook info (only needed
 * for OpenSSL < 1.1.0; later versions are internally thread-safe)
 */

typedef struct ThreadLock_ {
    pthread_mutex_t     mutex;
} ThreadLock;


typedef struct ThreadSafetyInfo_ {

    bool                isInitialized;
    ThreadLock*         pLocks;
    int                 numLocks;

} ThreadSafetyInfo;
#endif // PSL_OPENSSL_LEGACY_INIT


typedef struct PslOpensslInitState_ {
    /// This mutex protects our openssl initialization and uninitialization logic
    pthread_mutex_t         mutex;


    bool                    isInitialized;  ///< TRUE, if openssl is initialized
    PmSockOpensslInitType   initType;

    PslRefcount             refCount;       ///< initializer refcount

#if PSL_OPENSSL_LEGACY_INIT
    ThreadSafetyInfo        threadSafety;
#endif
} PslOpensslInitState;


static PslOpensslInitState gInitState = {
    /// "fast", non-recursive mutex
    .mutex                  = PTHREAD_MUTEX_INITIALIZER,
    .isInitialized          = false,
    .initType               = 0,
    .refCount               = {0},

#if PSL_OPENSSL_LEGACY_INIT
    .threadSafety = {
        .isInitialized  = false,
        .pLocks         = NULL,
        .numLocks       = 0
    }
#endif
};

static PslError
init_openssl_already_locked(PmSockOpensslInitType initType);

static PslError
init_openssl_low(PmSockOpensslInitType initType);

static void uninit_openssl_low(void);


#if PSL_OPENSSL_LEGACY_INIT
static void thread_safety_init(ThreadSafetyInfo* pData);

static void thread_safety_cleanup(ThreadSafetyInfo* pData);

static unsigned long get_thread_id_cb(void);

static void lock_or_unlock_cb(int mode, int type, const char *file, int line);
#endif // PSL_OPENSSL_LEGACY_INIT



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslInit(PmSockOpensslInitType const initType)
{
    PslError        rc = PSL_ERR_NONE;

    pthread_mutex_lock(&gInitState.mutex);

    rc = init_openssl_already_locked(initType);

    pthread_mutex_unlock(&gInitState.mutex);

    return rc;
}//PmSockOpensslInit



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslUninit(void)
{
    pthread_mutex_lock(&gInitState.mutex);

    PSL_LOG_DEBUG("%s: isInitialized=%d, current initType=%d", __func__,
                  (int)gInitState.isInitialized, (int)gInitState.initType);

    /// @note if triggered, this assertion indicates excess of Uninit calls
    ///       (or _unlikely_ overflow of unbalanced Init calls: over 4 Billion)
    PSL_ASSERT(gInitState.isInitialized);

    if (gInitState.isInitialized &&
        psl_refcount_atomic_unref(&gInitState.refCount)) {
        uninit_openssl_low();

        gInitState.isInitialized = false;
    }

    pthread_mutex_unlock(&gInitState.mutex);

    return PSL_ERR_NONE;
}//PmSockOpensslUninit



/* =========================================================================
 * =========================================================================
 */
PslError
PmSockOpensslThreadCleanup(void)
{
    PslError pslerr = PSL_ERR_NONE;

    pthread_mutex_lock(&gInitState.mutex);

    PSL_LOG_DEBUG("%s: isInitialized=%d, current initType=%d", __func__,
                  (int)gInitState.isInitialized, (int)gInitState.initType);

    if (gInitState.isInitialized) {
        /**
         * @note OPENSSL_thread_stop() is the OpenSSL 1.1+ replacement
         *       for the legacy ERR_remove_state(0)/
         *       ERR_remove_thread_state(NULL) thread-local cleanup;
         *       psl_openssl_compat.h maps it back for older versions
         */
        OPENSSL_thread_stop();
    }
    else {
        pslerr = PSL_ERR_NOT_ALLOWED;
        PSL_LOG_CRITICAL(
            "%s: USAGE ERROR: %s called outside the scope of libpalmsocket's " \
            "initialization of OpenSSL", __func__, __func__);
    }

    pthread_mutex_unlock(&gInitState.mutex);

    return pslerr;
}//PmSockOpensslThreadCleanup


/* =========================================================================
 * =========================================================================
 */
PslError psl_openssl_init_conditional(PmSockOpensslInitType const initType)
{
    PslError rc = PSL_ERR_NONE;

    pthread_mutex_lock(&gInitState.mutex);

    PSL_LOG_DEBUG("%s: initType=%d", __func__, (int)initType);

    if (gInitState.isInitialized) {
        psl_refcount_atomic_ref(&gInitState.refCount);
    }

    else {
        rc = init_openssl_already_locked(initType);
    }

    pthread_mutex_unlock(&gInitState.mutex);

    return rc;
}



/** ========================================================================
 * init_openssl_already_locked(): the worker function that
 * implements PmSockOpensslInit() and is also used by
 * psl_openssl_init_conditional(). Assumes that this module's
 * mutex is already locked.
 *
 * =========================================================================
 */
static PslError
init_openssl_already_locked(PmSockOpensslInitType const initType)
{
    PslError        rc = PSL_ERR_NONE;

    PSL_LOG_DEBUG("%s: initType=%d", __func__, (int)initType);

    if (gInitState.isInitialized) {
        if (kPmSockOpensslInitType_singleThreaded == gInitState.initType &&
            kPmSockOpensslInitType_multiThreaded == initType) {
            PSL_LOG_CRITICAL("%s: ERROR: multi-threaded openssl initialization " \
                             "is NOT allowed after single-threaded initialization",
                             __func__);
            rc = PSL_ERR_NOT_ALLOWED;
        }
        else {
            psl_refcount_atomic_ref(&gInitState.refCount);
        }
    }
    else {
        rc = init_openssl_low(initType);
        if (PSL_ERR_NONE == rc) {
            gInitState.isInitialized = true;
            gInitState.initType = initType;
            psl_refcount_init(&gInitState.refCount, "PSL_OPENSSL_INIT",
                              &gInitState);

        }
    }

    return rc;
}//init_openssl_already_locked


/** ========================================================================
 * init_openssl_low(): performs the requested openssl
 * initialization. Assumes our module's mutex is locked.
 *
 * @note With OpenSSL 1.1+, both initType variants receive the same
 *       treatment: the library is internally thread-safe, so the
 *       legacy CRYPTO_set_locking_callback()/CRYPTO_set_id_callback()
 *       hooks that kPmSockOpensslInitType_multiThreaded used to
 *       install no longer exist (they were no-op macros in 1.1.x and
 *       were removed in 3.0).  With older OpenSSL, the hooks are
 *       installed as before.
 *
 * @param initType
 *
 * @return PslError 0 on success; non-zero PslError code on
 *         failure
 *
 * =========================================================================
 */
static PslError
init_openssl_low(PmSockOpensslInitType const initType)
{
    PSL_LOG_INFO("%s: ENTERING", __func__);

    PSL_ASSERT(kPmSockOpensslInitType_singleThreaded == initType ||
               kPmSockOpensslInitType_multiThreaded  == initType);

#if PSL_OPENSSL_LEGACY_INIT
    /**
     * @note SSL_library_init() is neither reentrant nor
     *       thread-safe.  This probably applies to
     *       SSL_load_error_strings(), etc.
     */
    PSL_LOG_DEBUG("%s: Calling SSL_library_init()", __func__);
    if (!SSL_library_init()) {
        PSL_LOG_FATAL("%s: ERROR: OpenSSL SSL_library_init() failed.",
                      __func__);
        return PSL_ERR_OPENSSL;
    }

    PSL_LOG_DEBUG("%s: Calling SSL_load_error_strings()", __func__);
    SSL_load_error_strings();

    if (kPmSockOpensslInitType_multiThreaded  == initType) {
        PSL_LOG_DEBUG("%s: Calling thread_safety_init", __func__);
        thread_safety_init(&gInitState.threadSafety);
    }
#else
    PSL_LOG_DEBUG("%s: Calling OPENSSL_init_ssl()", __func__);
    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                          OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        PSL_LOG_FATAL("%s: ERROR: OPENSSL_init_ssl() failed.", __func__);
        return PSL_ERR_OPENSSL;
    }
#endif // PSL_OPENSSL_LEGACY_INIT

    /**
     * @note /dev/urandom emits bytes from a PRNG and will produce
     *       bytes forever. Seeding with 1k byes is appropriate.
     *       /dev/random produces better quality randomness but can
     *       block, so urandom is better here.
     *
     * @note OpenSSL 1.1+ auto-seeds its DRBG from the OS on first
     *       use, so a failure here is logged but not treated as fatal.
     */
    PSL_LOG_DEBUG("%s: Calling RAND_load_file()", __func__);
    const char* const urandomPath = "/dev/urandom";
    int const numRandBytesRead = RAND_load_file(urandomPath, 1024);
    if (numRandBytesRead <= 0) {
        PSL_LOG_WARNING("%s: WARNING: RAND_load_file(%s) read no bytes " \
                        "(rc=%d); relying on OpenSSL's automatic seeding",
                        __func__, urandomPath, numRandBytesRead);
    }
    else {
        PSL_LOG_DEBUG("%s: RAND_load_file() read %d bytes from %s",
                      __func__, numRandBytesRead, urandomPath);
    }

    PSL_LOG_INFO("%s: LEAVING WITH SUCCESS", __func__);

    return PSL_ERR_NONE;
}


/** ========================================================================
 * uninit_openssl_low(): Uninitializes openssl.  Assumes our
 * module's mutex is locked.
 *
 * @note OpenSSL 1.1+ registers its own atexit() cleanup
 *       (OPENSSL_cleanup); the legacy explicit cleanup calls
 *       (ERR_free_strings, EVP_cleanup, ENGINE_cleanup,
 *       CONF_modules_free) are deprecated no-ops there, so this
 *       function only has real work on older OpenSSL.
 *
 * =========================================================================
 */
static void
uninit_openssl_low(void)
{
    PSL_LOG_INFO("%s: ENTERING", __func__);

#if PSL_OPENSSL_LEGACY_INIT
    /**
     * @note Properly cleaning up openssl's memory allocations is
     *       very important for the purpose of analyzing an
     *       application's memory leaks.  Unfortunately, there is
     *       no SSL_library_cleanup(), so openssl cleanup is pure
     *       voodoo.  Search the WEB for "Leaks in
     *       SSL_Library_init()" to see other threads on this topic.
     */

    /**
     * Thread-safe cleanup, apparently
     */
    ENGINE_cleanup();
    CONF_modules_free();


    /**
     * global non-thread-safe cleanup after all SSL activity is
     * terminated
     */
    ERR_free_strings();
    EVP_cleanup();

    /// DO THIS LAST:
    thread_safety_cleanup(&gInitState.threadSafety);
#endif // PSL_OPENSSL_LEGACY_INIT

    PSL_LOG_INFO("%s: LEAVING", __func__);
}


#if PSL_OPENSSL_LEGACY_INIT

/** ========================================================================
 * thread_safety_init(): Initializes openssl thread-safety
 * hooks. Assumes our module's mutex is locked.
 *
 * =========================================================================
 */
static void
thread_safety_init(ThreadSafetyInfo* const pData)
{
    PSL_LOG_DEBUG("%s: ENTERING", __func__);

    PSL_ASSERT(pData);
    PSL_ASSERT(!pData->isInitialized);
    PSL_ASSERT(!pData->numLocks);
    PSL_ASSERT(!pData->pLocks);

    int const numLocks = CRYPTO_num_locks();

    PSL_LOG_DEBUG("%s: Initializing %d thread locks", __func__, numLocks);

    pData->pLocks = malloc(numLocks * sizeof(pData->pLocks[0]));
    if (numLocks && !pData->pLocks) {
        /// Hard stop: proceeding without the lock array would leave
        /// openssl without thread protection and lock_or_unlock_cb
        /// dereferencing NULL
        PSL_LOG_FATAL("%s: FATAL ERROR: failed to allocate %d thread " \
                      "locks; aborting", __func__, numLocks);
        abort();
    }
    pData->numLocks = numLocks;

    int i;
    for (i=0; i < pData->numLocks; i++) {
        PSL_LOG_DEBUGLOW("%s: Creating thread lock type=%d",
                         __func__, i);

        /// @note The locks are of the non-recursive kind by default
        int const mutexInitRes = pthread_mutex_init(&(pData->pLocks[i].mutex),
                                                    NULL);
        if (0 != mutexInitRes) {
            PSL_LOG_CRITICAL("%s: ERROR: pthread_mutex_init returned unexpected " \
                             "non-zero value: %d", __func__, mutexInitRes);
        }
    }

    PSL_LOG_DEBUG("%s: Calling CRYPTO_set_id_callback", __func__);
    CRYPTO_set_id_callback(get_thread_id_cb);

    PSL_LOG_DEBUG("%s: Calling CRYPTO_set_locking_callback", __func__);
    CRYPTO_set_locking_callback(lock_or_unlock_cb);

    pData->isInitialized = true;

    PSL_LOG_DEBUG("%s: LEAVING", __func__);
}


/** ========================================================================
 * thread_safety_cleanup(): Uninitializes openssl thread-safety
 * hooks
 *
 * =========================================================================
 */
static void
thread_safety_cleanup(ThreadSafetyInfo* const pData)
{
    PSL_LOG_DEBUG("%s", __func__);

    if (!pData->isInitialized) {
        PSL_LOG_DEBUG("%s: thread-safety was not initialized, so nothing to do",
                      __func__);
        return;
    }

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    PSL_LOG_DEBUG("%s: Destroying %d thread locks",
                  __func__, pData->numLocks);

    int i;
    for (i=0; i < pData->numLocks; i++) {
        PSL_LOG_DEBUGLOW("%s: Destroying thread lock type=%d",
                         __func__, i);

        pthread_mutex_destroy(&(pData->pLocks[i].mutex));
    }

    free(pData->pLocks);

    pData->numLocks = 0;
    pData->pLocks = NULL;
    pData->isInitialized = false;
}


/** ========================================================================
 * get_thread_id_cb(): callback function registered via
 * CRYPTO_set_id_callback()
 *
 * @return unsigned long
 *
 * =========================================================================
 */
static unsigned long
get_thread_id_cb(void)
{
    unsigned long const threadId = (unsigned long)pthread_self();

    PSL_LOG_DEBUGLOW("%s: returning threadId=%lu", __func__, threadId);

    return threadId;
}


/** ========================================================================
 * lock_or_unlock_cb(): callback function registered via
 * CRYPTO_set_locking_callback()
 *
 * @param mode
 * @param type
 * @param file
 * @param line
 *
 * =========================================================================
 */
static void
lock_or_unlock_cb(int const mode, int const type, const char* const file,
                  int const line)
{
    PSL_LOG_DEBUGLOW("%s: threadId=%lu, mode=0x%X, type=%d, caller=%s:%d",
                     __func__, CRYPTO_thread_id(), (unsigned)mode, type,
                     file, line);

    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(gInitState.threadSafety.pLocks[type].mutex));
    }
    else {
        pthread_mutex_unlock(&(gInitState.threadSafety.pLocks[type].mutex));
    }
}

#endif // PSL_OPENSSL_LEGACY_INIT
