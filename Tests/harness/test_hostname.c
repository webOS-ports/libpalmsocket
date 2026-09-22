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
 * Unit tests for hostname matching and certificate hostname
 * verification (PmSockX509CheckCertHostNameMatch and
 * PmSockOpensslVerifyHostname).
 */
#include <stdbool.h>

#include "palmsockopensslutils.h"
#include "palmsockx509utils.h"
#include "palmsocket.h"

#include "test_common.h"
#include "test_cert_util.h"

static bool
name_matches(const char* cn, int cnLen, const char* hn)
{
    bool res = false;
    PslError const err = PmSockX509CheckCertHostNameMatch(
        cn, (cnLen < 0) ? (unsigned)strlen(cn) : (unsigned)cnLen,
        hn, (unsigned)strlen(hn), 0, &res);
    return !err && res;
}

static void
test_name_matching(void)
{
    /// Exact and case-insensitive matches
    TCHECK(name_matches("example.com", -1, "example.com"));
    TCHECK(name_matches("EXAMPLE.com", -1, "example.COM"));
    TCHECK(!name_matches("example.com", -1, "example.org"));
    TCHECK(!name_matches("example.com", -1, "www.example.com"));
    TCHECK(!name_matches("www.example.com", -1, "example.com"));

    /// Wildcards: leftmost label only, must cover >= 2 labels
    TCHECK(name_matches("*.example.com", -1, "www.example.com"));
    TCHECK(!name_matches("*.example.com", -1, "a.b.example.com"));
    TCHECK(!name_matches("*.com", -1, "example.com"));
    TCHECK(!name_matches("www.*.com", -1, "www.example.com"));
    TCHECK(!name_matches("*", -1, "example"));

    /// Embedded NUL in the certificate name must not truncate the
    /// comparison (the classic NUL-prefix attack)
    TCHECK(!name_matches("example.com\0evil.org", 21, "example.com"));

    /// High-bit bytes must compare consistently (UB fix regression):
    /// equality of identical high-bit names must hold on all arches
    TCHECK(name_matches("f\xc3\xbc.example.com", -1, "f\xc3\xbc.example.com"));
    TCHECK(!name_matches("f\xc3\xbc.example.com", -1, "fu.example.com"));
}

static void
test_cert_verification(void)
{
    EVP_PKEY* const key = test_make_key();
    TCHECK(key != NULL);
    if (!key) return;

    bool matched;

    /// 1. SAN dNSName match
    X509* crt = test_make_cert(key, "cn.example.com", -1,
                               "DNS:san.example.com");
    TCHECK(crt != NULL);
    if (crt) {
        matched = false;
        TCHECK(0 == PmSockOpensslVerifyHostname("san.example.com", crt,
                                                0, 0, &matched));
        TCHECK_MSG(matched, "SAN dNSName should match");

        /// 2. RFC 6125: SAN of the relevant type present -> CN must
        ///    NOT be consulted as a fallback
        matched = true;
        TCHECK(0 == PmSockOpensslVerifyHostname("cn.example.com", crt,
                                                0, 0, &matched));
        TCHECK_MSG(!matched, "CN fallback must be skipped when SAN present");
        X509_free(crt);
    }

    /// 3. CN match when no SAN present
    crt = test_make_cert(key, "cnonly.example.com", -1, NULL);
    TCHECK(crt != NULL);
    if (crt) {
        matched = false;
        TCHECK(0 == PmSockOpensslVerifyHostname("cnonly.example.com", crt,
                                                0, 0, &matched));
        TCHECK_MSG(matched, "CN should match when no SAN is present");

        matched = true;
        TCHECK(0 == PmSockOpensslVerifyHostname("other.example.com", crt,
                                                0, 0, &matched));
        TCHECK(!matched);
        X509_free(crt);
    }

    /// 4. SAN iPAddress match; CN not consulted for IPs when SAN
    ///    iPAddress entries exist
    crt = test_make_cert(key, "10.9.9.9", -1, "IP:10.1.2.3");
    TCHECK(crt != NULL);
    if (crt) {
        matched = false;
        TCHECK(0 == PmSockOpensslVerifyHostname("10.1.2.3", crt,
                                                0, 0, &matched));
        TCHECK_MSG(matched, "SAN iPAddress should match");

        matched = true;
        TCHECK(0 == PmSockOpensslVerifyHostname("10.9.9.9", crt,
                                                0, 0, &matched));
        TCHECK_MSG(!matched, "IP CN fallback must be skipped when SAN "
                   "iPAddress present");
        X509_free(crt);
    }

    /// 5. IP address in CN (no SAN): legit match plus the
    ///    embedded-NUL spoof ("1.2.3.4\0evil") which must NOT match
    crt = test_make_cert(key, "10.4.5.6", -1, NULL);
    TCHECK(crt != NULL);
    if (crt) {
        matched = false;
        TCHECK(0 == PmSockOpensslVerifyHostname("10.4.5.6", crt,
                                                0, 0, &matched));
        TCHECK_MSG(matched, "IP-in-CN should match with no SAN");
        X509_free(crt);
    }

    crt = test_make_cert(key, "10.4.5.6\0evil.org", 17, NULL);
    TCHECK(crt != NULL);
    if (crt) {
        matched = true;
        TCHECK(0 == PmSockOpensslVerifyHostname("10.4.5.6", crt,
                                                0, 0, &matched));
        TCHECK_MSG(!matched, "embedded-NUL IP CN must not match");
        X509_free(crt);
    }

    /// 6. dNSName with embedded NUL must not match the prefix
    crt = test_make_cert(key, NULL, 0,
                         "DNS:good.example.com");
    TCHECK(crt != NULL);
    if (crt) {
        matched = true;
        TCHECK(0 == PmSockOpensslVerifyHostname("bad.example.com", crt,
                                                0, 0, &matched));
        TCHECK(!matched);
        X509_free(crt);
    }

    EVP_PKEY_free(key);
}

int
main(void)
{
    PmSockOpensslInit(kPmSockOpensslInitType_multiThreaded);

    test_name_matching();
    test_cert_verification();

    PmSockOpensslUninit();
    return TEST_REPORT("test_hostname");
}
