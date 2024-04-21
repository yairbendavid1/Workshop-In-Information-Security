#ifndef _PROXY_H_
#define _PROXY_H_

#include "fw.h"
#include "FWConnectionDevice.h"

connection_t *from_client_to_proxy_connection(__be32 *client_ip, __be16 *client_port);
connection_t *is_port_proxy_exist(__be16 *proxy_port);
int is_proxy(connection_t *conn, direction_t *direction, __be16 *port);
void fix_checksum(struct sk_buff *skb);
ssize_t set_proxy_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t add_ftp_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

#endif