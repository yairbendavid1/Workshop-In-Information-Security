#include "fw.h"
#include "FWProxyDecive.h"
#include "FWConnectionDevice.h"


connection_t *proxy_ports[1 << 16];
extern struct list_head connection_table;
extern __u32 connection_table_size;





connection_t *from_client_to_proxy_connection(__be32 *client_ip, __be16 *client_port){
    connection_t *conn;
    list_for_each_entry(conn, &connection_table, list_node){
        if (conn->intity.ip == *client_ip && conn->outity.port == *client_port){
            return conn;
        }
    }
    return NULL;
}

connection_t *is_port_proxy_exist(__be16 *proxy_port){
    return proxy_ports[*proxy_port];
}

int create_proxy(connection_t *conn, direction_t *direction, __be16 *port){
    if (*direction == DIRECTION_IN){
        return 0;
    }
    
    if (packet->dst_port == 80)
    {
        conn->proxy.proxy_state = REG_HTTP;
        return 1;
    }
    if (packet->dst_port == 21)
    {
        conn->proxy.proxy_state = FTP_CREATE;
        return 1;
    }
    return 0;
}

/* void copy_from_buff_and_increase(const char **buf_ptr, void *var, size_t n){
    memcpy(var, *buf_ptr, n);
    *buf_ptr += n;
}
*/


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
    if (proxy == NULL)
    {
        printk("set_proxy_port: can't find proxy")
    }

    conn->proxy.proxy_port = proxy_port;
    proxy_table[proxy_port] = conn;

    return bsize;
}

