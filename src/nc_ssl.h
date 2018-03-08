#ifndef _NC_SSL_H_
#define _NC_SSL_H_

#include <nc_core.h>
#include <sys/uio.h>

// Configure SSL for a connection. Updates `conn->ssl` on success.
rstatus_t setup_ssl(struct conn *conn);
// teardown_ssl(struct conn *conn); // TODO: would this ever get used?

// version of `man writev` that uses SSL_write() to write a vector of
// to data an SSL structure.
ssize_t SSL_writev(SSL *ssl, const struct iovec *iov, int iovcnt);


// Copy the contents of iovcnt vectors from iov into buf, in order.
// Exposed for testing.
void copy_all_to_buffer(char* buf, size_t buflen, const struct iovec *iov, int iovcnt);

#endif