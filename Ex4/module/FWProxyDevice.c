#include "fw.h"
#include "FWProxyDevice.h"
#include "FWConnectionDevice.h"
#include "FWRuleDevice.h"


connection_t *proxy_table[1 << 16];
extern struct list_head connection_table;
extern __u32 connection_table_size;





connection_t *from_client_to_proxy_connection(__be32 *client_ip, __be16 *client_port){
    connection_t *conn;
    list_for_each_entry(conn, &connection_table, node){
        if (conn->intity.ip == *client_ip && conn->outity.port == *client_port){
            return conn;
        }
    }
    return NULL;
}

connection_t *is_port_proxy_exist(__be16 *proxy_port){
    return proxy_table[*proxy_port];
}

int create_proxy(connection_t *conn, direction_t *direction, __be16 *port){
    if (*direction == DIRECTION_IN){
        return 0;
    }
    
    if (*port == 80)
    {
        conn->proxy.proxy_state = REG_HTTP;
        return 1;
    }
    if (*port == 21)
    {
        conn->proxy.proxy_state = FTP_CREATE;
        return 1;
    }
    return 0;
}



// This function gets a packet after modifying it and fix the checksums
void fix_checksum(struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    // Fix TCP header checksum
    int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check =
        tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));

    // Fix IP header checksum
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    skb->ip_summed = CHECKSUM_NONE;
    // skb->csum_valid = 0;
}



// This function is the store function for the proxy port attribute
// Its called when the user writes to the proxy port attribute
// The user will send the buffer with the proxy port and the client ip and port
// The format of the buffer is (client_ip, client_port, proxy_port)
// The function will extract the client ip and port and the proxy port and set the proxy port in the proxy table.
ssize_t set_proxy_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    __u16 bsize = sizeof(__be32) + 2 * sizeof(__be16);
    __be32 client_ip;
    __be16 client_port;
    __be16 proxy_port;
    connection_t *conn;

    if (count < bsize)
    {
        return 0;
    }

    // Should get (client_ip, client_port, proxy_port)
    copy_from_buff_and_increase(&buf, &client_ip, sizeof(client_ip));
    copy_from_buff_and_increase(&buf, &client_port, sizeof(client_port));
    copy_from_buff_and_increase(&buf, &proxy_port, sizeof(proxy_port));
    
    conn = from_client_to_proxy_connection(&client_ip, &client_port);
    if (conn == NULL)
    {
        printk("set_proxy_port: can't find proxy");
    }

    conn->proxy.proxy_port = proxy_port;
    proxy_table[proxy_port] = conn;

    return bsize;
}



ssize_t add_ftp_data(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    __be32 ftp_ip, server_ip;
    __be16 ftp_port;
    connection_t *conn;
    __u16 FTP_ADD_SIZE = 2 * sizeof(__be32) + sizeof(__be16);
    if (count < FTP_ADD_SIZE)
    {
        return 0;
    }

    // Should get (client_ip, server_ip, ftp_data_port)
    copy_from_buff_and_increase(&buf, &ftp_ip, sizeof(ftp_ip));
    copy_from_buff_and_increase(&buf, &server_ip, sizeof(server_ip));
    copy_from_buff_and_increase(&buf, &ftp_port, sizeof(ftp_port));

    // Add an FTP data connection
    conn = create_empty_connection();

    // Set identifiers
    conn->intity.ip = ftp_ip;
    conn->intity.port = ftp_port;
    conn->outity.ip = server_ip;
    conn->outity.port = 0; // Wildcard - match to any port
    

    // Initialize connection state
    conn->state.status = PRESYN;
    conn->state.direction = DIRECTION_IN; // Now the client becomes the server

    // Non-proxy connection
    conn->proxy.proxy_state = FTP_DATA;
    conn->proxy.proxy_port = 1;

    return FTP_ADD_SIZE;
}

