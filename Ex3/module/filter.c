#include "filter.h"
#include "fw.h"

// This function is called when a packet is received at one of the hook points.
unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // First we need to allocate some memory for the fields of the packet that store in the sk_buff.
    // we will use those fields to check if the packet is allowed or not.
    direction_t packet_direction; // the direction of the packet
    __be32 packet_src_ip; // the source ip of the packet
    __be32 packet_dst_ip; // the destination ip of the packet
    __be16 packet_src_port; // the source port of the packet
    __be16 packet_dst_port; // the destination port of the packet
    __u8 packet_protocol; // the protocol of the packet
    ack_t packet_ack; // the ack of the packet

    // Now we will parse the packet and fill the fields with the values from the packet.
    set_direction(skb, &packet_direction, const struct nf_hook_state *state);
    set_src_dst_ip(skb, &packet_src_ip, &packet_dst_ip);
    set_src_dst_port(skb, &packet_src_port, &packet_dst_port);
    set_protocol(skb, &packet_protocol);
    set_ack(skb, &packet_ack);
}


// This function get a packet and extract the direction from it and store it in the packet_direction.
void set_direction(struct sk_buff *skb, direction_t *packet_direction, const struct nf_hook_state *state) {
    char * in_device_name = state->in->name;
    char * out_device_name = state->out->name;
    
    if(strcmp(in_device_name, IN_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, OUT_NET_DEVICE_NAME) == 0) { // if the packet is coming from inside to outside
        *packet_direction = DIRECTION_OUT;
    } else if(strcmp(in_device_name, OUT_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, IN_NET_DEVICE_NAME) == 0) { // if the packet is coming from outside to inside
        *packet_direction = DIRECTION_OUT;
    } else {
        *packet_direction = DIRECTION_ANY;
    }
}


// This function get a packet and extract the source and destination ip from it and store them in the packet_src_ip and packet_dst_ip.
void set_src_dst_ip(struct sk_buff *skb, __be32 *packet_src_ip, __be32 *packet_dst_ip) {
    // Get IP fields
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    *packet_src_ip = ntohl(packet_ip_header->saddr);
    *packet_dst_ip = ntohl(packet_ip_header->daddr);
}


// This function get a packet and extract the source and destination port from it and store them in the packet_src_port and packet_dst_port.
void set_src_dst_port(struct sk_buff *skb, __be16 *packet_src_port, __be16 *packet_dst_port) {
    // Get transport layer protocol field, and declaring headers
    struct tcphdr *packet_tcp_header;
    struct udphdr *packet_udp_header;
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    switch (packet_ip_header->protocol) {
        case PROT_TCP: {
            // Get TCP port fields
            packet_tcp_header = tcp_hdr(skb);
            *packet_src_port = ntohs(packet_tcp_header->source);
            *packet_dst_port = ntohs(packet_tcp_header->dest);
            break;
        }
        case PROT_UDP: {
            // Get UDP port fields
            packet_udp_header = udp_hdr(skb);
            *packet_src_port = ntohs(packet_udp_header->source);
            *packet_dst_port = ntohs(packet_udp_header->dest);
            break;
        }
    }
}


// This function get a packet and extract the protocol from it and store it in the packet_protocol.
void set_protocol(struct sk_buff *skb, __u8 *packet_protocol) {
    // Get transport layer protocol field, and declaring headers
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    *packet_protocol = packet_ip_header->protocol;
}


// This function get a packet and extract the ack field from it and store it in the packet_ack.
void set_ack(struct sk_buff *skb, ack_t *packet_ack) {
    // Get transport layer protocol field, and declaring headers
    struct tcphdr *packet_tcp_header;
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    if (packet_ip_header->protocol == PROT_TCP) {
        // Get TCP port fields
        packet_tcp_header = tcp_hdr(skb);
        *packet_ack = packet_tcp_header->ack ? ACK_YES : ACK_NO;
    }
}

