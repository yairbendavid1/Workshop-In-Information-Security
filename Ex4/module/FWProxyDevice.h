#ifndef _PROXY_H_
#define _PROXY_H_

#include "fw.h"
#include "FWConnectionDevice.h"

connection_t *from_client_to_proxy_connection(__be32 *client_ip, __be16 *client_port);


#endif