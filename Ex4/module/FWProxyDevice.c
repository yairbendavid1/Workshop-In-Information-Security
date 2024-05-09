#include "fw.h"
#include "FWProxyDevice.h"
#include "FWConnectionDevice.h"
#include "FWRuleDevice.h"
#include "PacketHandler.h"


connection_t *proxy_table[1 << 16];
extern struct list_head connection_table;
extern __u32 connection_table_size;

// This function is called on a newly created connection, and checks for a proxy connection.
// IF the connection is a proxy connection, it will update the connection entry and the routing.
// As for now, the function only checks for HTTP connections starting within the internal network.
// IT WILL SUPPORT FTP IN THE FUTURE, AND WILL BE EXTENDED TO SUPPORT OTHER PROTOCOLS IN THE NEXT EXERCISES.
// The function will return 1 if the connection is a proxy connection, and 0 otherwise.
int create_proxy(packet_information_t *packet_info, connection_t *conn){
    // We first need to check the direction
    if (packet_info->direction == DIRECTION_OUT){
        // We only support HTTP for now
        if (packet_info->dst_port == 80){ 
            conn->proxy.proxy_state = HTTP_FROM_INTERNAL_NETWORK;
            conn->state.status = PROXY;
            return is_proxy_connection(packet_info, conn);
        }
    }
    return 0;
}

// This function will find the connection of the proxy according to the packet information
// The function will return the connection of the proxy if found, and NULL otherwise.
// We know that only packets from server to clinet cannot find connection using is_connection_exist,
// so we will use this function to find the connection of the proxy, assuming the sender is the server.
connection_t *find_proxy_connection(packet_information_t *packet_info){
    //since we know that the sender is the server, and the clien is always the one who initiate the connection,
    //the port of the FW, which is the dst port is already in the proxy table!
    connection_t *conn = is_port_proxy_exist(&(packet_info->dst_port));
    if (conn == NULL){
        print_message("find_proxy_connection: can't find proxy");
        return NULL;
    }
    // Now we need to check that the server credentials are the same as the sender of the packet
    // since we dont know in which network the server is, we will split into cases using the proxy state
    if (conn->proxy.proxy_state == HTTP_FROM_INTERNAL_NETWORK){
        // In this case, the server is in the external network
        if (conn->outity.ip == packet_info->src_ip && conn->outity.port == packet_info->src_port){
            print_message("find_proxy_connection: found proxy\n");
            return conn;
        }
    } 
    print_message("find_proxy_connection: can't find proxy\n");
    return NULL;
}
    



// This function checks if the packet is part of a proxy connection.
// If it does, it will route the packet to the proxy connection according to the proxy state.
// The function will return 1 if the packet is part of a proxy connection, and 0 otherwise.

// NOTE THAT THIS FUNCTION IS USED AT PRE_ROUTING HOOK ONLY!
// This means that our options are only internal->proxy and external->proxy
int is_proxy_connection(packet_information_t *packet_info, connection_t *conn){
    if (conn == NULL){ // If the connection is NULL, return 0
        conn = find_proxy_connection(packet_info);
        if (conn == NULL){
            return 0;
        }
    }
    if( conn->state.status != PROXY){ // If the connection is not a proxy connection, return 0
        return 0;
    }
    struct sk_buff *skb = packet_info->skb;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);

    // we need to check the directions
    if (packet_info->direction == DIRECTION_OUT){
        // We are in the internal->proxy case
        // In this case we need to change the destination IP to the proxy IP
        iph->daddr = htonl(FW_IN_LEG);

        // we also need to change the destination port (in some cases) to the proxy port 
        // We need to check the proxy state to know which port to use
        if (conn->proxy.proxy_state == HTTP_FROM_INTERNAL_NETWORK){
            tcph->dest = htons(HTTP_FROM_INTERNAL_NETWORK_PORT);
        }
        else{
            // We don't support other protocols for now
            return 0;
        }
        // Fix the checksums
        fix_checksum(skb);
        print_message("I2P: Packet from internal was proxied to FW\n");
        return 1;
    }
    else{
        // We are in the external->proxy case
        // In this case we need to change the source IP to the proxy IP
        iph->saddr = htonl(FW_OUT_LEG);

        // AS FOR NOW, WE DON'T SUPPORT PROXYING FROM EXTERNAL NETWORK

        // Fix the checksums
        fix_checksum(skb);
        print_message("E2P: Packet from External was proxied to FW\n");
        return 1;
    }
    // We should never reach here
    return 0;
}

// This function will change the source route of proxied packet to the original sender

// NOTE THAT THIS FUNCTION IS USED AT LOCAL_OUT HOOK ONLY!
// This means that our options are only proxy->internal and proxy->external
void route_proxy_packet(packet_information_t *packet_info){
    connection_t *conn;
    struct sk_buff *skb = packet_info->skb;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);

    // we need to check the directions
    if (packet_info->direction == DIRECTION_OUT){
        // We are in the proxy->external case.

        // In this case we need to change the source IP to IP of the original sender.
        // To do so, we first need to find the connection of the original sender.
        conn = is_port_proxy_exist(&(packet_info->src_port));
        if (conn == NULL){
            print_message("P2E: route_proxy_packet: can't find proxy");
            return;
        }
        // we will check that the extity is the same as the destination of the packet since we dont clean the proxy table.
        if (conn->outity.ip != packet_info->dst_ip || conn->outity.port != packet_info->dst_port){
            print_message("P2E: route_proxy_packet: connection doesn't match");
            return;
        } 

        // Now we can change the source IP to the original source IP
        iph->saddr = conn->intity.ip;
        // Fix the checksums
        fix_checksum(skb);
        print_message("P2E: Source of Proxied Packet from FW to External has been changed.\n");
        return;
    }
    else{
        // We are in the proxy->internal case
        // In this case we need to change both the IP and the port of the packet to the original sender

        // To do so, we first need to find the connection of the original sender using the client credentials.
        conn = from_client_to_proxy_connection(&(packet_info->dst_ip), &(packet_info->dst_port));
        if (conn == NULL){
            print_message("P2I: route_proxy_packet: can't find proxy");
            return;
        }
        // Now we can change the source IP and port to the original sender
        iph->saddr = conn->outity.ip;
        if (conn->proxy.proxy_state == HTTP_FROM_INTERNAL_NETWORK){
            tcph->source = htons(80);
            printk("HTTP\n");
        }
        printk("IP and Port: %d %d\n", htonl(conn->outity.ip), htons(conn->outity.port));
        printk("IP and Port: %d %d\n", conn->outity.ip, conn->outity.port);
        // Fix the checksums
        fix_checksum(skb);
        print_message("P2I: Source of Proxied Packet from FW to Internal has been changed.\n");
        return;
    }
    return;
}


connection_t *from_client_to_proxy_connection(__be32 *client_ip, __be16 *client_port){
    connection_t *conn;
    list_for_each_entry(conn, &connection_table, node){
        if (conn->intity.ip == *client_ip && conn->intity.port == *client_port){
            return conn;
        }
    }
    return NULL;
}

connection_t *is_port_proxy_exist(__be16 *proxy_port){
    return proxy_table[*proxy_port];
}

// int is_proxy(connection_t *conn, direction_t *direction, __be16 *port){
//     if (*direction == DIRECTION_IN){
//         return 0;
//     }
    
//     if (*port == 80)
//     {
//         conn->proxy.proxy_state = REG_HTTP;
//         return 1;
//     }
//     if (*port == 21)
//     {
//         conn->proxy.proxy_state = FTP_CREATE;
//         return 1;
//     }
//     return 0;
// }



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
        print_message("set_proxy_port: can't find proxy");
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
    conn->state.status = INIT;
    conn->state.direction = DIRECTION_IN; // Now the client becomes the server

    // Non-proxy connection
    conn->proxy.proxy_state = FTP_DATA;
    conn->proxy.proxy_port = 1;

    return FTP_ADD_SIZE;
}

