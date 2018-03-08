#ifndef _NC_SSL_H_
#define _NC_SSL_H_

#include <nc_core.h>
#include <sys/uio.h>

// Configure SSL for a connection. Updates `conn->ssl` on success.
rstatus_t setup_ssl(struct conn *conn);
// teardown_ssl(struct conn *conn); // TODO: would this ever get used?

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
ssize_t nc_ssl_read(SSL *ssl, void *buf, int num);


// Copy the contents of iovcnt vectors from iov into buf, in order.
// Exposed for testing.
void copy_all_to_buffer(char* buf, size_t buflen, const struct iovec *iov, int iovcnt);

#endif