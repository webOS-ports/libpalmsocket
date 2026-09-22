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
 * Integration/stress test: plaintext and TLS loopback between two
 * libpalmsocket channels over a socketpair, driven by a single
 * GMainLoop.  The client writes a payload; the server echoes it
 * back; the client verifies the round-trip.
 *
 * Usage: test_loopback [iterations] [payload-bytes]
 *   iterations   number of connect/transfer/teardown cycles for
 *                EACH of plain and TLS mode (default 3)
 *   payload      bytes per transfer (default 256KiB)
 *
 * Designed to also serve as the device stress test (e.g.
 * "test_loopback 200 1048576" hammers channel setup/teardown and
 * bulk transfer), and to run under AddressSanitizer.
 */
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>

#include <openssl/ssl.h>

#include "palmsocket.h"

#include "test_common.h"
#include "test_cert_util.h"

typedef struct {
    GMainLoop*          loop;
    PmSockIOChannel*    ch;
    PmSockWatch*        watch;
    bool                isServer;
    bool                connected;
    bool                failed;
    PslError            connErr;

    const uint8_t*      sendBuf;    ///< client only
    size_t              sendLen;
    size_t              sentCnt;
    uint8_t*            recvBuf;
    size_t              recvLen;    ///< expected total
    size_t              recvCnt;

    size_t              echoedCnt;  ///< server: bytes echoed back
    int*                doneCounter;
} Endpoint;


static void
on_connect_done(PmSockIOChannel* const ch, void* const userData,
                PslError const errorCode)
{
    Endpoint* const ep = (Endpoint*)userData;
    (void)ch;
    ep->connErr = errorCode;
    if (errorCode) {
        ep->failed = true;
        fprintf(stderr, "connect completion error (%s): %d (%s)\n",
                ep->isServer ? "server" : "client",
                errorCode, PmSockErrStringFromError(errorCode));
        g_main_loop_quit(ep->loop);
        return;
    }
    ep->connected = true;
    if (*ep->doneCounter > 0 && 0 == --(*ep->doneCounter)) {
        g_main_loop_quit(ep->loop);
    }
}

/**
 * Client watch: pump writes until sendLen sent, read echoes until
 * recvLen received.
 */
static gboolean
client_watch_cb(GIOChannel* const gio, GIOCondition const cond,
                gpointer const userData)
{
    Endpoint* const ep = (Endpoint*)userData;

    if ((cond & (G_IO_ERR | G_IO_NVAL)) != 0) {
        ep->failed = true;
        g_main_loop_quit(ep->loop);
        return false;
    }

    if ((cond & G_IO_OUT) && ep->sentCnt < ep->sendLen) {
        gsize written = 0;
        GIOStatus const st = g_io_channel_write_chars(
            gio, (const gchar*)ep->sendBuf + ep->sentCnt,
            ep->sendLen - ep->sentCnt, &written, NULL);
        ep->sentCnt += written;
        if (G_IO_STATUS_ERROR == st) {
            ep->failed = true;
            g_main_loop_quit(ep->loop);
            return false;
        }
    }

    if ((cond & (G_IO_IN | G_IO_HUP)) && ep->recvCnt < ep->recvLen) {
        gsize nread = 0;
        GIOStatus const st = g_io_channel_read_chars(
            gio, (gchar*)ep->recvBuf + ep->recvCnt,
            ep->recvLen - ep->recvCnt, &nread, NULL);
        ep->recvCnt += nread;
        if (G_IO_STATUS_ERROR == st || G_IO_STATUS_EOF == st) {
            ep->failed = true;
            g_main_loop_quit(ep->loop);
            return false;
        }
    }

    if (ep->recvCnt >= ep->recvLen) {
        g_main_loop_quit(ep->loop); ///< round-trip complete
        return false;
    }

    /// Update the monitored conditions
    GIOCondition const want =
        (GIOCondition)(((ep->sentCnt < ep->sendLen) ? G_IO_OUT : 0) | G_IO_IN);
    (void)PmSockWatchUpdate(ep->watch, want);
    return true;
}

/**
 * Server watch: echo whatever arrives straight back.
 */
static gboolean
server_watch_cb(GIOChannel* const gio, GIOCondition const cond,
                gpointer const userData)
{
    Endpoint* const ep = (Endpoint*)userData;

    if ((cond & (G_IO_ERR | G_IO_NVAL)) != 0) {
        ep->failed = true;
        g_main_loop_quit(ep->loop);
        return false;
    }

    /// Read into the pending buffer
    if ((cond & (G_IO_IN | G_IO_HUP)) && ep->recvCnt < ep->recvLen) {
        gsize nread = 0;
        GIOStatus const st = g_io_channel_read_chars(
            gio, (gchar*)ep->recvBuf + ep->recvCnt,
            ep->recvLen - ep->recvCnt, &nread, NULL);
        ep->recvCnt += nread;
        if (G_IO_STATUS_ERROR == st || G_IO_STATUS_EOF == st) {
            ep->failed = true;
            g_main_loop_quit(ep->loop);
            return false;
        }
    }

    /// Echo back anything read but not yet written
    if (ep->echoedCnt < ep->recvCnt) {
        gsize written = 0;
        GIOStatus const st = g_io_channel_write_chars(
            gio, (const gchar*)ep->recvBuf + ep->echoedCnt,
            ep->recvCnt - ep->echoedCnt, &written, NULL);
        ep->echoedCnt += written;
        if (G_IO_STATUS_ERROR == st) {
            ep->failed = true;
            g_main_loop_quit(ep->loop);
            return false;
        }
    }

    GIOCondition const want =
        (GIOCondition)(G_IO_IN |
                       ((ep->echoedCnt < ep->recvCnt) ? G_IO_OUT : 0));
    (void)PmSockWatchUpdate(ep->watch, want);
    return true;
}

static bool
setup_endpoint(Endpoint* const ep, PmSockThreadContext* const threadCtx,
               GMainLoop* const loop, int const fd, bool const isServer)
{
    memset(ep, 0, sizeof(*ep));
    ep->loop = loop;
    ep->isServer = isServer;

    if (PmSockCreateChannel(threadCtx, 0,
                            isServer ? "t_server" : "t_client", &ep->ch)) {
        return false;
    }
    if (PmSockSetConnectedFD(ep->ch, fd, 0)) {
        return false;
    }
    return true;
}

static bool
attach_watch(Endpoint* const ep, GIOCondition const cond, GMainContext* mctx)
{
    if (PmSockCreateWatch(ep->ch, cond, &ep->watch)) {
        return false;
    }
    g_source_set_callback((GSource*)ep->watch,
                          (GSourceFunc)(void (*)(void))
                          (ep->isServer ? &server_watch_cb : &client_watch_cb),
                          ep, NULL);
    g_source_attach((GSource*)ep->watch, mctx);
    return true;
}

static void
teardown_endpoint(Endpoint* const ep)
{
    if (ep->watch) {
        g_source_destroy((GSource*)ep->watch);
        g_source_unref((GSource*)ep->watch);
        ep->watch = NULL;
    }
    if (ep->ch) {
        g_io_channel_unref((GIOChannel*)ep->ch);
        ep->ch = NULL;
    }
    g_free(ep->recvBuf);
    ep->recvBuf = NULL;
}

/**
 * One full loopback cycle.  crypto=false: plaintext.  crypto=true:
 * TLS with the server's self-signed cert trusted by the client.
 */
static void
run_cycle(PmSockThreadContext* const threadCtx, GMainContext* const mctx,
          bool const crypto, size_t const payloadLen,
          EVP_PKEY* const srvKey, X509* const srvCert)
{
    int fds[2];
    TCHECK(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    GMainLoop* const loop = g_main_loop_new(mctx, false);

    Endpoint client, server;
    TCHECK(setup_endpoint(&client, threadCtx, loop, fds[0], false));
    TCHECK(setup_endpoint(&server, threadCtx, loop, fds[1], true));

    uint8_t* const payload = g_malloc(payloadLen);
    size_t i;
    for (i = 0; i < payloadLen; i++) {
        payload[i] = (uint8_t)(i * 31 + 7);
    }

    client.sendBuf = payload;
    client.sendLen = payloadLen;
    client.recvLen = payloadLen;
    client.recvBuf = g_malloc(payloadLen);

    server.recvLen = payloadLen;
    server.recvBuf = g_malloc(payloadLen);

    int pendingConnects = 2;
    client.doneCounter = &pendingConnects;
    server.doneCounter = &pendingConnects;

    PmSockSSLContext* cliSslCtx = NULL;
    PmSockSSLContext* srvSslCtx = NULL;

    if (crypto) {
        TCHECK(0 == PmSockSSLCtxNew("t_server_ssl", &srvSslCtx));
        TCHECK(0 == PmSockSSLCtxNew("t_client_ssl", &cliSslCtx));

        SSL_CTX* const srvCtx = PmSockSSLCtxPeekOpensslContext(srvSslCtx);
        TCHECK(1 == SSL_CTX_use_certificate(srvCtx, srvCert));
        TCHECK(1 == SSL_CTX_use_PrivateKey(srvCtx, srvKey));

        /// Client trusts the server's self-signed cert, so full
        /// certificate verification stays enabled
        SSL_CTX* const cliCtx = PmSockSSLCtxPeekOpensslContext(cliSslCtx);
        TCHECK(1 == X509_STORE_add_cert(SSL_CTX_get_cert_store(cliCtx),
                                        srvCert));

        PmSockSetUserData(client.ch, &client);
        PmSockSetUserData(server.ch, &server);

        TCHECK(0 == PmSockAcceptCrypto(server.ch, srvSslCtx, NULL,
                                       &on_connect_done));
        TCHECK(0 == PmSockConnectCrypto(client.ch, cliSslCtx, NULL,
                                        &on_connect_done));
    }
    else {
        PmSockSetUserData(client.ch, &client);
        PmSockSetUserData(server.ch, &server);
        TCHECK(0 == PmSockConnectPlain(client.ch, &on_connect_done));
        TCHECK(0 == PmSockConnectPlain(server.ch, &on_connect_done));
    }

    /// Phase 1: wait for both connect completions
    g_main_loop_run(loop);
    TCHECK_MSG(client.connected && server.connected,
               "%s connect failed: client=%d server=%d",
               crypto ? "TLS" : "plain", client.connErr, server.connErr);

    if (client.connected && server.connected) {
        /// Phase 2: transfer
        pendingConnects = 0;
        TCHECK(attach_watch(&client, (GIOCondition)(G_IO_OUT | G_IO_IN),
                            mctx));
        TCHECK(attach_watch(&server, G_IO_IN, mctx));

        g_main_loop_run(loop);

        TCHECK_MSG(!client.failed && !server.failed, "transfer I/O failed");
        TCHECK(client.recvCnt == payloadLen);
        TCHECK_MSG(0 == memcmp(client.recvBuf, payload, payloadLen),
                   "echoed payload mismatch");
    }

    teardown_endpoint(&client);
    teardown_endpoint(&server);

    if (cliSslCtx) PmSockSSLCtxUnref(cliSslCtx);
    if (srvSslCtx) PmSockSSLCtxUnref(srvSslCtx);

    g_free(payload);
    g_main_loop_unref(loop);
    /// The channels close their fds themselves
}

int
main(int argc, char** argv)
{
    int const iterations = (argc > 1) ? atoi(argv[1]) : 3;
    size_t const payloadLen = (argc > 2) ? (size_t)atol(argv[2])
                                         : (size_t)(256 * 1024);

    PmSockThreadContext* threadCtx = NULL;
    if (PmSockThreadCtxNewFromGMain(NULL, "t_harness", &threadCtx)) {
        fprintf(stderr, "thread ctx creation failed\n");
        return 2;
    }
    GMainContext* const mctx = PmSockThreadCtxPeekGMainContext(threadCtx);

    EVP_PKEY* const srvKey = test_make_key();
    X509* const srvCert = srvKey
        ? test_make_cert(srvKey, "loopback.test", -1, "DNS:loopback.test")
        : NULL;
    TCHECK(srvKey && srvCert);

    int iter;
    for (iter = 0; iter < iterations && !gTestFailures; iter++) {
        run_cycle(threadCtx, mctx, false, payloadLen, srvKey, srvCert);
        run_cycle(threadCtx, mctx, true, payloadLen, srvKey, srvCert);
        if (iterations > 10 && 0 == (iter % 10)) {
            printf("  iteration %d/%d\n", iter, iterations);
            fflush(stdout);
        }
    }

    if (srvCert) X509_free(srvCert);
    if (srvKey) EVP_PKEY_free(srvKey);
    PmSockThreadCtxUnref(threadCtx);

    return TEST_REPORT("test_loopback");
}
