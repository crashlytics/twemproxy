#ifndef _SSL_WRITEV_H_
#define _SSL_WRITEV_H_

#include <openssl/ssl.h>

ssize_t
SSL_writev (SSL *ssl, const struct iovec *vector, int count);

#endif