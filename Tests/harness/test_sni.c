/* @@@LICENSE
*
* Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
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
 * TLS Server Name Indication on client channels.
 *
 * A libpalmsocket client connects over real TCP to a libpalmsocket
 * server on the loopback interface, by name and by address, and the
 * server records the SNI it was sent:
 *
 *   "localhost"   the ClientHello carries server_name "localhost"
 *   "127.0.0.1"   no server_name at all (RFC 6066 forbids an IP
 *                 address literal there)
 *
 * Without SNI, servers that pick a certificate by name answer with
 * a placeholder: Gmail's is self-signed, "No SNI provided - please
 * fix your client.", which failed verification and made Gmail IMAP
 * accounts impossible to add.
 */
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <glib-unix.h>

#include <openssl/ssl.h>

#include "palmsocket.h"

#include "test_common.h"
#include "test_cert_util.h"

typedef struct {
    GMainLoop*          loop;
    int                 pending;    ///< connect completions still due
    PslError            cliErr;
    PslError            srvErr;
    bool                cliDone;
    bool                srvDone;

    /// What the server saw in the ClientHello
    bool                sniCallbackRan;
    char                sni[256];   ///< "" when none was sent

    /// Server side, created once the listener accepts
    int                 listenFd;
    PmSockThreadContext* threadCtx;
    PmSockSSLContext*   srvSslCtx;
    PmSockIOChannel*    srvCh;
} SniRun;

static SniRun* gRun;    ///< for the OpenSSL servername callback

static int
on_servername(SSL* const ssl, int* const al, void* const arg)
{
    (void)al;
    (void)arg;
    const char* const name = SSL_get_servername(ssl,
                                                TLSEXT_NAMETYPE_host_name);
    gRun->sniCallbackRan = true;
    g_strlcpy(gRun->sni, name ? name : "", sizeof(gRun->sni));
    return SSL_TLSEXT_ERR_OK;
}

static void
note_done(SniRun* const run)
{
    if (--run->pending <= 0) {
        g_main_loop_quit(run->loop);
    }
}

static void
on_client_connected(PmSockIOChannel* const ch, void* const userData,
                    PslError const errorCode)
{
    (void)ch;
    SniRun* const run = (SniRun*)userData;
    run->cliErr = errorCode;
    run->cliDone = true;
    note_done(run);
}

static void
on_server_accepted(PmSockIOChannel* const ch, void* const userData,
                   PslError const errorCode)
{
    (void)ch;
    SniRun* const run = (SniRun*)userData;
    run->srvErr = errorCode;
    run->srvDone = true;
    note_done(run);
}

static gboolean
on_listen_readable(gint const fd, GIOCondition const cond,
                   gpointer const userData)
{
    (void)cond;
    SniRun* const run = (SniRun*)userData;

    int const conn = accept(fd, NULL, NULL);
    TCHECK(conn >= 0);
    if (conn < 0) {
        g_main_loop_quit(run->loop);
        return G_SOURCE_REMOVE;
    }

    TCHECK(0 == PmSockCreateChannel(run->threadCtx, 0, "t_sni_server",
                                    &run->srvCh));
    TCHECK(0 == PmSockSetConnectedFD(run->srvCh, conn, 0));
    PmSockSetUserData(run->srvCh, run);
    TCHECK(0 == PmSockAcceptCrypto(run->srvCh, run->srvSslCtx, NULL,
                                   &on_server_accepted));
    return G_SOURCE_REMOVE;
}

/**
 * Connects a client channel to the loopback listener by @hostStr
 * and checks the SNI the server saw against @expectSni ("" for none).
 */
static void
run_case(PmSockThreadContext* const threadCtx, GMainContext* const mctx,
         EVP_PKEY* const srvKey, X509* const srvCert,
         const char* const hostStr, const char* const expectSni)
{
    SniRun run;
    memset(&run, 0, sizeof(run));
    gRun = &run;
    run.threadCtx = threadCtx;
    run.loop = g_main_loop_new(mctx, false);
    run.pending = 2;

    /// Listener on 127.0.0.1, ephemeral port
    run.listenFd = socket(AF_INET, SOCK_STREAM, 0);
    TCHECK(run.listenFd >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TCHECK(0 == bind(run.listenFd, (struct sockaddr*)&sa, sizeof(sa)));
    TCHECK(0 == listen(run.listenFd, 1));
    socklen_t saLen = sizeof(sa);
    TCHECK(0 == getsockname(run.listenFd, (struct sockaddr*)&sa, &saLen));
    int const port = ntohs(sa.sin_port);

    GSource* const listenSrc = g_unix_fd_source_new(run.listenFd, G_IO_IN);
    g_source_set_callback(listenSrc, (GSourceFunc)(void (*)(void))
                          &on_listen_readable, &run, NULL);
    g_source_attach(listenSrc, mctx);

    /// Server context: the test cert, and a callback that records SNI
    TCHECK(0 == PmSockSSLCtxNew("t_sni_server_ssl", &run.srvSslCtx));
    SSL_CTX* const srvCtx = PmSockSSLCtxPeekOpensslContext(run.srvSslCtx);
    TCHECK(1 == SSL_CTX_use_certificate(srvCtx, srvCert));
    TCHECK(1 == SSL_CTX_use_PrivateKey(srvCtx, srvKey));
    SSL_CTX_set_tlsext_servername_callback(srvCtx, &on_servername);

    /// Client context trusts the test cert
    PmSockSSLContext* cliSslCtx = NULL;
    TCHECK(0 == PmSockSSLCtxNew("t_sni_client_ssl", &cliSslCtx));
    SSL_CTX* const cliCtx = PmSockSSLCtxPeekOpensslContext(cliSslCtx);
    TCHECK(1 == X509_STORE_add_cert(SSL_CTX_get_cert_store(cliCtx), srvCert));

    PmSockIOChannel* cliCh = NULL;
    TCHECK(0 == PmSockCreateChannel(threadCtx, 0, "t_sni_client", &cliCh));
    TCHECK(0 == PmSockSetConnectAddress(cliCh, AF_INET, hostStr, port));
    PmSockSetUserData(cliCh, &run);
    TCHECK(0 == PmSockConnectCrypto(cliCh, cliSslCtx, NULL,
                                    &on_client_connected));

    g_main_loop_run(run.loop);

    TCHECK_MSG(run.cliDone && 0 == run.cliErr,
               "%s: client connect failed: %d", hostStr, run.cliErr);
    TCHECK_MSG(run.srvDone && 0 == run.srvErr,
               "%s: server accept failed: %d", hostStr, run.srvErr);
    TCHECK_MSG(run.sniCallbackRan,
               "%s: server never saw a ClientHello", hostStr);
    TCHECK_MSG(0 == strcmp(run.sni, expectSni),
               "%s: server saw SNI '%s', expected '%s'",
               hostStr, run.sni, expectSni);
    printf("  %-10s -> SNI '%s'\n", hostStr, run.sni);

    g_source_destroy(listenSrc);
    g_source_unref(listenSrc);
    if (cliCh) g_io_channel_unref((GIOChannel*)cliCh);
    if (run.srvCh) g_io_channel_unref((GIOChannel*)run.srvCh);
    PmSockSSLCtxUnref(cliSslCtx);
    PmSockSSLCtxUnref(run.srvSslCtx);
    close(run.listenFd);
    g_main_loop_unref(run.loop);
    gRun = NULL;
}

int
main(void)
{
    PmSockThreadContext* threadCtx = NULL;
    if (PmSockThreadCtxNewFromGMain(NULL, "t_sni", &threadCtx)) {
        fprintf(stderr, "thread ctx creation failed\n");
        return 2;
    }
    GMainContext* const mctx = PmSockThreadCtxPeekGMainContext(threadCtx);

    EVP_PKEY* const srvKey = test_make_key();
    X509* const srvCert = srvKey
        ? test_make_cert(srvKey, "localhost", -1,
                         "DNS:localhost,IP:127.0.0.1")
        : NULL;
    TCHECK(srvKey && srvCert);

    if (srvKey && srvCert) {
        run_case(threadCtx, mctx, srvKey, srvCert, "localhost", "localhost");
        run_case(threadCtx, mctx, srvKey, srvCert, "127.0.0.1", "");
    }

    if (srvCert) X509_free(srvCert);
    if (srvKey) EVP_PKEY_free(srvKey);
    PmSockThreadCtxUnref(threadCtx);

    return TEST_REPORT("test_sni");
}
