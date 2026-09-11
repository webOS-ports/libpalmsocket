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
 * Runtime certificate/key generation helpers for the test harness.
 * Works with OpenSSL 0.9.8 through 3.x.
 */
#ifndef PSL_TEST_CERT_UTIL_H__
#define PSL_TEST_CERT_UTIL_H__

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 * Generates a fresh RSA key wrapped in an EVP_PKEY. Returns NULL on
 * failure.
 */
static EVP_PKEY*
test_make_key(void)
{
    EVP_PKEY* const pkey = EVP_PKEY_new();
    if (!pkey) {
        return NULL;
    }

    RSA* const rsa = RSA_new();
    BIGNUM* const e = BN_new();
    if (!rsa || !e || !BN_set_word(e, RSA_F4) ||
        !RSA_generate_key_ex(rsa, 2048, e, NULL) ||
        !EVP_PKEY_assign_RSA(pkey, rsa)) {
        if (rsa) RSA_free(rsa);
        if (e) BN_free(e);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    BN_free(e);
    return pkey;    // pkey owns rsa now
}

/**
 * Builds a self-signed certificate.
 *
 * @param pkey     key to bind and sign with
 * @param cn       Common Name value (may contain embedded NULs when
 *                 cnLen names their position); NULL to omit CN
 * @param cnLen    length of cn in bytes, or -1 for strlen(cn)
 * @param sanSpec  subjectAltName extension conf string (e.g.
 *                 "DNS:example.com,IP:1.2.3.4"), or NULL for none
 *
 * @return X509* or NULL on failure
 */
static X509*
test_make_cert(EVP_PKEY* const pkey,
               const char* const cn, int const cnLen,
               const char* const sanSpec)
{
    X509* const crt = X509_new();
    if (!crt) {
        return NULL;
    }

    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_get_notBefore(crt), -60L * 60);
    X509_gmtime_adj(X509_get_notAfter(crt), 60L * 60 * 24 * 365);
    X509_set_pubkey(crt, pkey);

    X509_NAME* const name = X509_get_subject_name(crt);
    if (cn) {
        if (!X509_NAME_add_entry_by_txt(
                name, "CN", MBSTRING_ASC, (const unsigned char*)cn,
                (cnLen < 0) ? (int)strlen(cn) : cnLen, -1, 0)) {
            X509_free(crt);
            return NULL;
        }
    }
    X509_set_issuer_name(crt, name);    // self-signed

    if (sanSpec) {
        X509_EXTENSION* const ext = X509V3_EXT_conf_nid(
            NULL, NULL, NID_subject_alt_name, (char*)sanSpec);
        if (!ext) {
            X509_free(crt);
            return NULL;
        }
        X509_add_ext(crt, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (!X509_sign(crt, pkey, EVP_sha256())) {
        X509_free(crt);
        return NULL;
    }

    return crt;
}

#endif // PSL_TEST_CERT_UTIL_H__
