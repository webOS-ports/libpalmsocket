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

/**
 * Regression tests for PmSockOpensslMatchCertInStore:
 *
 * - the NULL X509_OBJECT crash from the broken openssl-1.1.1 port
 *   (crashed whenever a store cert's subject matched)
 * - the CRL type-confusion in the matching-subject scan
 * - basic match / no-match behavior
 */
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "palmsockopensslutils.h"
#include "palmsocket.h"

#include "test_common.h"
#include "test_cert_util.h"

static X509_CRL*
make_crl(EVP_PKEY* const key, X509* const issuer)
{
    X509_CRL* const crl = X509_CRL_new();
    if (!crl) {
        return NULL;
    }
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(issuer));
    ASN1_TIME* const now = ASN1_TIME_new();
    X509_gmtime_adj(now, 0);
    X509_CRL_set_lastUpdate(crl, now);
    ASN1_TIME_free(now);
    if (!X509_CRL_sign(crl, key, EVP_sha256())) {
        X509_CRL_free(crl);
        return NULL;
    }
    return crl;
}

int
main(void)
{
    PmSockOpensslInit(kPmSockOpensslInitType_multiThreaded);

    EVP_PKEY* const key = test_make_key();
    TCHECK(key != NULL);
    if (!key) return TEST_REPORT("test_cert_store");

    /// An "installed" cert in the store and a peer cert with the SAME
    /// subject but different key/signature (the attack scenario that
    /// crashed the broken port)
    X509* const installed = test_make_cert(key, "store.example.com", -1, NULL);
    X509* const sameSubjDifferentCert =
        test_make_cert(key, "store.example.com", -1, "DNS:other.example.com");
    X509* const unrelated = test_make_cert(key, "unrelated.example.com", -1,
                                           NULL);
    TCHECK(installed && sameSubjDifferentCert && unrelated);

    X509_STORE* const store = X509_STORE_new();
    TCHECK(store != NULL);
    TCHECK(1 == X509_STORE_add_cert(store, installed));

    /// A CRL sharing the store: the old scan would have called
    /// X509_get_subject_name(NULL) on it
    X509_CRL* const crl = make_crl(key, installed);
    TCHECK(crl != NULL);
    if (crl) {
        TCHECK(1 == X509_STORE_add_crl(store, crl));
    }

    X509_STORE_CTX* const ctx = X509_STORE_CTX_new();
    TCHECK(ctx != NULL);
    TCHECK(1 == X509_STORE_CTX_init(ctx, store, installed, NULL));

    bool matched;

    /// 1. Exact cert present in store -> match
    matched = false;
    TCHECK(0 == PmSockOpensslMatchCertInStore(ctx, installed, 0, &matched));
    TCHECK_MSG(matched, "installed cert should match itself in store");

    /// 2. Same subject, different cert -> subject lookup succeeds
    ///    (this is where the NULL X509_OBJECT crashed), X509_cmp
    ///    mismatches, the scan runs past the CRL without crashing,
    ///    and the result is no-match
    matched = true;
    TCHECK(0 == PmSockOpensslMatchCertInStore(ctx, sameSubjDifferentCert,
                                              0, &matched));
    TCHECK_MSG(!matched, "same-subject different cert must not match");

    /// 3. Unrelated subject -> no match, no crash
    matched = true;
    TCHECK(0 == PmSockOpensslMatchCertInStore(ctx, unrelated, 0, &matched));
    TCHECK(!matched);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    if (crl) X509_CRL_free(crl);
    X509_free(installed);
    X509_free(sameSubjDifferentCert);
    X509_free(unrelated);
    EVP_PKEY_free(key);

    PmSockOpensslUninit();
    return TEST_REPORT("test_cert_store");
}
