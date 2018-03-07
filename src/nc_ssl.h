#ifndef _NC_SSL_H_
#define _NC_SSL_H_

#include <nc_core.h>

// Configure SSL for a connection. Updates `conn->ssl` on success.
rstatus_t setup_ssl(struct conn *conn);

// teardown_ssl(struct conn *conn); // TODO: would this ever get used?

// TODO: add read/write calls here?

#endif