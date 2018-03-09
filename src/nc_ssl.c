#include <nc_ssl.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

static void
log_ssl_error_stack(void) {
    long unsigned int ssl_error_code;
    while ((ssl_error_code = ERR_get_error()) != 0) {
        log_error("SSL error: %s", ERR_error_string(ssl_error_code, NULL));
    }
}

static void
log_ssl_error_code(int error_code) {
    log_error("SSL failed with error code: %d", error_code);

    char buf[256];
    ERR_error_string_n((unsigned long)error_code, buf, sizeof(buf));
    log_error(buf);

    log_error("error: %s", ERR_error_string(ERR_get_error(), NULL));
    switch(error_code) {
        case SSL_ERROR_NONE: log_error("error string: SSL_ERROR_NONE"); break;
        case SSL_ERROR_ZERO_RETURN: log_error("error string: SSL_ERROR_ZERO_RETURN"); break;
        case SSL_ERROR_WANT_READ: log_error("error string: SSL_ERROR_WANT_READ"); break;
        case SSL_ERROR_WANT_WRITE: log_error("error string: SSL_ERROR_WANT_WRITE"); break;
        case SSL_ERROR_WANT_CONNECT: log_error("error string: SSL_ERROR_WANT_CONNECT"); break;
        case SSL_ERROR_WANT_ACCEPT: log_error("error string: SSL_ERROR_WANT_ACCEPT"); break;
        case SSL_ERROR_WANT_X509_LOOKUP: log_error("error string: SSL_ERROR_WANT_X509_LOOKUP"); break;
        case SSL_ERROR_SYSCALL: log_error("error string: SSL_ERROR_SYSCALL"); break;
        case SSL_ERROR_SSL: log_error("error string: SSL_ERROR_SSL"); break;
    }

    if (error_code == SSL_ERROR_SSL) {
        log_ssl_error_stack();
    }
}

static rstatus_t
block_until_read_or_write(int socket_descriptor, int timeout_secs) {
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(socket_descriptor, &fds);
    tv.tv_sec = timeout_secs;
    tv.tv_usec = 0;
    int select_result = select(socket_descriptor+1, &fds, &fds, NULL, &tv);

    if (select_result <= 0) {
        log_debug(LOG_VERB, "select failed with code: %d", select_result);
        return NC_ERROR;
    }

    return NC_OK;
}

static rstatus_t
do_ssl_connect(SSL *ssl) {
    int connect_status;
    while ((connect_status = SSL_connect(ssl)) != 1) {
        int code = SSL_get_error(ssl, connect_status);

        if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
            // This means that the socket needs to do a read or write first.
            // Since the socket is nonblocking, we can just wait until it is done, per the man page.
            block_until_read_or_write(SSL_get_fd(ssl), 2);
        }
        else {
            log_error("Failing SSL_connect due to unhandled error.");
            log_ssl_error_code(code);
            return NC_ERROR;
        }
    }

    log_debug(LOG_VERB, "Successfuly completed SSL connection.");
    return NC_OK;
}

rstatus_t
nc_setup_ssl(struct conn *conn, struct string *host_cert_path, struct string *host_key_path, struct string *ca_file_path) {
    char *cert_path = (char *)host_cert_path->data;
    char *key_path = (char *)host_key_path->data;
    char *ca_path = (char *)ca_file_path->data;

    log_debug(LOG_VERB, "Using %s", SSLeay_version(SSLEAY_VERSION));
    log_debug(LOG_VERB, "Connecting with cert: %s", cert_path);
    log_debug(LOG_VERB, "Connecting with key: %s", key_path);
    log_debug(LOG_VERB, "Connecting with ca file: %s", ca_path);

    SSL_CTX *ctx;
    SSL *ssl;

    // FIXME: can these 3 functions be called multiple times?
    SSL_library_init(); /* load encryption & hash algorithms for SSL */
    ERR_load_crypto_strings();
    SSL_load_error_strings(); /* load the error strings for good error reporting */

    ctx = SSL_CTX_new(SSLv23_method());

    if (ctx == NULL) {
        log_error("Error creating ssl context");
    }

    SSL_CTX_set_timeout(ctx, 5); // in seconds

    int use_cert = SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM);
    if (use_cert != 1) {
        log_error("Error loading ssl cert %s", cert_path);
        return NC_ERROR;
    }

    int use_private_key = SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM);
    if (use_private_key != 1) {
        log_error("Error loading ssl private key: %s", key_path);
        return NC_ERROR;
    }

    // TODO: can we specify separate locations for client verification and what is sent to the server (check with Brian on the specifics of this distinction)
    int use_ca = SSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    if (use_ca != 1) {
        log_error("Error loading ssl ca file: %s", ca_path);
        return NC_ERROR;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        log_error("Consistency error between private key and certificates. SSL error stack:");
        log_ssl_error_stack();
        return NC_ERROR;
    }

    ssl = SSL_new(ctx);

    if (ssl == NULL) {
        log_error("Error creating SSL structure. SSL error stack:");
        log_ssl_error_stack();
        return NC_ERROR;
    }

    SSL_set_fd(ssl, conn->sd);

    if (do_ssl_connect(ssl) != NC_OK) {
        return NC_ERROR;
    }

    log_debug(LOG_VERB, "SSL is set up for s %d.", conn->sd);

    conn->ssl = ssl;
    return NC_OK;
}

rstatus_t
nc_teardown_ssl(SSL *ssl) {
    int shutdown_status;
    while ((shutdown_status = SSL_shutdown(ssl)) <= 0) {
        if (shutdown_status == 0) {
            // 0 means shutdown is not yet finished and that the function should be called again.
            continue;
        }

        int code = SSL_get_error(ssl, shutdown_status);

        if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
            // This means that the socket needs to do a read or write first.
            // Since the socket is nonblocking, we can just wait until it is done, per the man page.
            block_until_read_or_write(SSL_get_fd(ssl), 2);
        }
        else {
            log_error("Failing SSL_write due to unhandled error.");
            log_ssl_error_code(code);
            return NC_ERROR;
        }
    }

    SSL_free(ssl);

    return NC_OK;
}

// Retry SSL_write if it encounters a SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error.
// Fail it if it encounters another error.
// Returns number of bytes written or -1 on failure.
static int
do_ssl_write(SSL *ssl, char * buf, int buflen) {
    int bytes_written;
    while ((bytes_written = SSL_write(ssl, buf, buflen)) <= 0) {
        int code = SSL_get_error(ssl, bytes_written);

        if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
            // This means that the socket needs to do a read or write first.
            // Since the socket is nonblocking, we can just wait until it is done, per the man page.
            block_until_read_or_write(SSL_get_fd(ssl), 2);
        }
        else {
            log_error("Failing SSL_write due to unhandled error.");
            log_ssl_error_code(code);
            return -1;
        }
    }

    return bytes_written;
}

ssize_t
nc_ssl_writev(SSL *ssl, const struct iovec *iov, int iovcnt) {
    size_t total_bytes = 0;
    for (int i = 0; i < iovcnt; i++) {
        total_bytes += iov[i].iov_len;
    }

    // FIXME: reconsider using this. it's allocated on the stack so could risk a stackoverflow.
    // It's not clear if SSL_write() does anything different with buf than write()
    char *buf = alloca(total_bytes);

    copy_all_to_buffer(buf, total_bytes, iov, iovcnt);

    if (total_bytes == 0) {
        // Calling SSL_write with 0 bytes to send causes undefined behavior.
        // Since there's nothing to send, return success.
        return 0;
    }

    // Must retry failed writes here since there's no guarantee that the caller of this
    // function will call it with the same arguments. However, it must since (from the man page):
    // When an SSL_write() operation has to be repeated because of SSL_ERROR_WANT_READ or
    // SSL_ERROR_WANT_WRITE, it must be repeated with the same arguments.
    return do_ssl_write(ssl, buf, (int)total_bytes);
}

ssize_t
nc_ssl_read(SSL *ssl, void *buf, size_t num) {
    int bytes_read;
    while ((bytes_read = SSL_read(ssl, buf, (int)num)) <= 0) {
        int code = SSL_get_error(ssl, bytes_read);

        if (code == SSL_ERROR_WANT_READ || code == SSL_ERROR_WANT_WRITE) {
            // This means that the socket needs to do a read or write first.
            // Since the socket is nonblocking, we can just wait until it is done, per the man page.
            block_until_read_or_write(SSL_get_fd(ssl), 2);
        }
        else if (code == SSL_ERROR_ZERO_RETURN) {
            // This is the equivalent of read() returning 0, which happens when the socket is closed.
            // Return 0 to mimic that behavior.
            return 0;
        }
        else {
            log_error("Failing SSL_read due to unhandled error.");
            log_ssl_error_code(code);
            return -1;
        }
    }

    return bytes_read;
}

static inline size_t
min(size_t a, size_t b) {
    if (a > b)
        return b;
    return a;
}

void
copy_all_to_buffer(char* buf, size_t buflen, const struct iovec *iov, int iovcnt) {
    size_t remaining_bytes = buflen;
    size_t to_copy_bytes;
    char *copy_loc = buf; // tracks where to next copy
    for (int i = 0; i < iovcnt; i++) {
        // Guard against buffer overflow.
        to_copy_bytes = min(iov[i].iov_len, remaining_bytes);

        memcpy(copy_loc, iov[i].iov_base, to_copy_bytes);
        copy_loc += to_copy_bytes;

        remaining_bytes -= to_copy_bytes;
        if (remaining_bytes == 0) {
            break;
        }
    }
}