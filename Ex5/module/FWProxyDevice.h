#ifndef _PROXY_H_
#define _PROXY_H_

#include "fw.h"
#include "FWConnectionDevice.h"
#include "PacketHandler.h"
#include "FWRuleDevice.h"


connection_t *from_client_to_proxy_connection(__be32 *client_ip, __be16 *client_port, direction_t direction);
connection_t *is_port_proxy_exist(__be16 *proxy_port);
//int is_proxy(connection_t *conn, direction_t *direction, __be16 *port);
int create_proxy(packet_information_t *packet_info, connection_t *conn);
int is_proxy_connection(packet_information_t *packet_info, connection_t *conn);
void route_proxy_packet(packet_information_t *packet_info);
void fix_checksum(struct sk_buff *skb);
ssize_t set_proxy_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
ssize_t add_ftp_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
int create_proxy(packet_information_t *packet_info, connection_t *conn);
int route_internal_proxy_connections(packet_information_t *packet_info, connection_t *conn);
int route_external_proxy_connections(packet_information_t *packet_info, connection_t *conn);
#endif