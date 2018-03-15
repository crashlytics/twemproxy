#ifndef _NC_SSL_H_
#define _NC_SSL_H_

#include <nc_core.h>
#include <sys/uio.h>

// Initializes OpenSSL library and error strings.
// Must be called before OpenSSL is used.
void nc_ssl_init(void);

// Configure SSL for a connection. Updates `conn->ssl` on success.
rstatus_t nc_setup_ssl(struct conn *conn, struct string *host_cert_path, struct string *host_key_path, struct string *ca_file_path);
// Shutdown the SSL connection and free `ssl`.
rstatus_t nc_teardown_ssl(SSL *ssl);

// Uses SSL_write() to write a vector of data over SSL with the same
// semantics as writev().
// Matches the return behavior of writev():
//  - On success, returns the number of bytes written.
//  - On failure, returns -1 and sets errno.
ssize_t nc_ssl_writev(SSL *ssl, const struct iovec *iov, int iovcnt);

// Version of SSL_read() with the same semantics as read().
// Matches the return behavior of writev():
//  - On success, returns the number of bytes read.
//  - On failure, returns -1 and sets errno.
ssize_t nc_ssl_read(SSL *ssl, void *buf, size_t num);


// Copies no more than n bytes from the iovcnt buffers described by iov into dest.
// Exposed for testing.
void copy_vectors_to_buffer(void* dest, size_t n, const struct iovec *iov, int iovcnt);

#endif