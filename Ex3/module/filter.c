#include "fw.h"
#include "rule.h"
#include "log.h"
#include "filter.h"

// This function is called when a packet is received at one of the hook points.
unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    printk("I snaped a pool");
    log_row_t log_for_packet;


    // First we need to allocate some memory for the fields of the packet that store in the sk_buff.
    // we will use those fields to check if the packet is allowed or not.
    direction_t packet_direction; // the direction of the packet
    __be32 packet_src_ip; // the source ip of the packet
    __be32 packet_dst_ip; // the destination ip of the packet
    __be16 packet_src_port; // the source port of the packet
    __be16 packet_dst_port; // the destination port of the packet
    __u8 packet_protocol; // the protocol of the packet
    ack_t packet_ack; // the ack of the packet
    __u8 is_XMAS_Packet; // bit that indicate if the packet is XMAS packet

    // Now we will parse the packet and fill the fields with the values from the packet.
    set_direction(skb, &packet_direction, state);
    set_src_dst_ip(skb, &packet_src_ip, &packet_dst_ip);
    set_src_dst_port(skb, &packet_src_port, &packet_dst_port);
    set_protocol(skb, &packet_protocol);
    set_ack_and_xmas(skb, &packet_ack, &is_XMAS_Packet);
    printk("%d", packet_protocol);

    // Loopbacks and packet with other protocols then TCP, UDP and ICMP are accepted withput log

    // if the packet is a loopback packet we will accept it without log
    if (((packet_src_ip & 0xFF000000) == 0x7F000000) || ((packet_dst_ip & 0xFF000000) == 0x7F000000)){
        return NF_ACCEPT;
    }
    printk("%d\n", packet_protocol == PROT_OTHER);
    // if the packet is not TCP, UDP or ICMP we will accept it without log
     if (packet_protocol == PROT_OTHER){
        // if packet_protocol is -1 it means the protocol is not TCP, UDP or ICMP and we will accept it
        return NF_ACCEPT;
     }

    // as now, we can fill the time, ip port and protocol fields of the log_row_t struct.
    // reason, action and count will be filled later.
    set_time_ip_and_port_for_log(&log_for_packet, &packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, &packet_protocol);


    // we need to check for XMAS packet
    if(is_XMAS_Packet){
        printk("XMAS PACKETT FOUND!\n");
        add_log(&log_for_packet, REASON_XMAS_PACKET, NF_DROP);
        return NF_DROP;
    }


    // If the rule table is not valid, then accept automatically (and log the action).
    if (is_valid_table() == 0)
    {
        printk(" PACKETT FOUND BUT NOT A VALID TABLE!\n");
        add_log(&log_for_packet, REASON_FW_INACTIVE, NF_ACCEPT);
        return NF_ACCEPT;
    }

    // now after we cover all the side cases we need to check if there is a rule that match to the packet.
    // We need to work based on the first rule matched to the packet.
    // if no rule is matched we need to drop the packet.

    rule_t *rule_table = get_rule_table();
    int ind;
    for(ind = 0; ind < get_rules_amount(); ind++){
        if (check_rule_for_packet(rule_table + ind, &packet_direction, &packet_src_ip, &packet_dst_ip, &packet_protocol, &packet_src_port, &packet_dst_port, &packet_ack)){
            // if we found a match we need to log the action and return the action.
            // when a rule match, the reason of the log will be the rule index.
            printk("PACKETT FOUND AND MATCH THE %d RULE!\n", ind);
            add_log(&log_for_packet, ind, (rule_table + ind)->action);
            return (rule_table + ind)->action;
        }
    }
    // if no match found we log the action and return NF_DROP.
    add_log(&log_for_packet, REASON_NO_MATCHING_RULE, NF_DROP);
    return NF_DROP;

}


// This function get a packet and extract the direction from it and store it in the packet_direction.
void set_direction(struct sk_buff *skb, direction_t *packet_direction, const struct nf_hook_state *state) {
    char * in_device_name = state->in->name;
    char * out_device_name = state->out->name;
    if(strcmp(in_device_name, IN_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, OUT_NET_DEVICE_NAME) == 0) { // if the packet is coming from inside to outside
        *packet_direction = DIRECTION_OUT;
        return;
      }
    if(strcmp(in_device_name, OUT_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, IN_NET_DEVICE_NAME) == 0) { // if the packet is coming from outside to inside
        *packet_direction = DIRECTION_IN;
        return;
    }
    *packet_direction = 0;
}


// This function get a packet and extract the source and destination ip from it and store them in the packet_src_ip and packet_dst_ip.
void set_src_dst_ip(struct sk_buff *skb, __be32 *packet_src_ip, __be32 *packet_dst_ip) {
    // Get IP fields
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    *packet_src_ip = packet_ip_header->saddr;
    *packet_dst_ip = packet_ip_header->daddr;
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
        case PROT_ICMP: {
          *packet_src_port = 0;
          *packet_dst_port = 0;
        }
    }
}


// This function get a packet and extract the protocol from it and store it in the packet_protocol.
void set_protocol(struct sk_buff *skb, __u8 *packet_protocol) {
    // Get transport layer protocol field, and declaring headers
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    if (packet_ip_header->protocol != PROT_TCP && packet_ip_header->protocol != PROT_UDP && packet_ip_header->protocol != PROT_ICMP){
        *packet_protocol = PROT_OTHER; // if the packet is not TCP or UDP or ICMP we want to accept it
        return;
     }
     *packet_protocol = packet_ip_header->protocol;

}


// This function get a packet and extract the ack field from it and store it in the packet_ack.
// Also, it checks if the packet is a XMAS packet and store the result in the is_XMAS_Packet.
void set_ack_and_xmas(struct sk_buff *skb, ack_t *packet_ack, __u8 *is_XMAS_Packet) {
    // Get transport layer protocol field, and declaring headers
    struct tcphdr *packet_tcp_header;
    struct iphdr *packet_ip_header;
    packet_ip_header = ip_hdr(skb);
    if (packet_ip_header->protocol == PROT_TCP) {
        // Get TCP port fields
        packet_tcp_header = tcp_hdr(skb);
        *packet_ack = packet_tcp_header->ack ? ACK_YES : ACK_NO;

        // Check for Christmas tree packet
        if (packet_tcp_header->fin && packet_tcp_header->urg && packet_tcp_header->psh)
        {
            *is_XMAS_Packet = 1;
            return;
        }
    }
    *is_XMAS_Packet = 0;
}


// This function get a rule and a packet and check if the rule is valid for the packet.
// If the rule is valid for the packet it returns 1, otherwise it returns 0.
int check_rule_for_packet(rule_t *rule, unsigned int *packet_direction, __be32 *packet_src_ip, __be32 *packet_dst_ip, __u8 *packet_protocol, __be16 *packet_src_port, __be16 *packet_dst_port, ack_t *packet_ack) {
    // Check if the direction is the same
    if ((rule->direction != DIRECTION_ANY) && (*packet_direction != rule->direction))
    {
      printk("dir\n");
        return 0;
    }

    // Check if the src ip is the same
    if (!check_packet_ip(rule->src_ip, rule->src_prefix_mask, rule->src_prefix_size, *packet_src_ip))
    {
        printk("src_ip\n");
        return 0;
    }

    // Check if the dst ip is the same
    if (!check_packet_ip(rule->dst_ip, rule->dst_prefix_mask, rule->dst_prefix_size, *packet_dst_ip))
    {
        printk("dst_ip\n");
        return 0;
    }


    // Check if the protocol is the same
    if (rule->protocol != PROT_ANY && rule->protocol != *packet_protocol)
    {
      printk("proc\n");
        return 0;
    }

    // since the protocol is the same we need to check if the packet is ICMP, UDP or TCP
    // in case of ICMP we don't need to check the ports and the ack - we have a match!
    // on udp, we need to check the ports - if they match we have a match!
    // on tcp, we need to check the ports and the ack - if they match we have a match!
    if (*packet_protocol == PROT_ICMP)
    {
        // if the protocol is ICMP we don't need to check the ports and the ack and we can finish.
        return 1;
    }
    else
    {
        // since the protocol is not ICMP we need to check the ports.
        if (!check_packet_port(rule->src_port, *packet_src_port))
        {
            printk("src_port\n");
            return 0;
        }
        if (!check_packet_port(rule->dst_port, *packet_dst_port))
        {
            printk("dst_port\n");
            return 0;
        }
        // if we are here it means that the ports are the same.
        // now we need to check if the protocol is UDP or TCP.
        if (*packet_protocol == PROT_UDP)
        {
            // If the protocol is UDP we don't need to check the ack and we can finish.
            return 1;
        }
        else
        {
            // If the protocol is TCP we need to check the ack.
            if (!check_packet_ack(rule->ack, *packet_ack))
            {
                printk("ack\n");
                return 0;
            }
            else
            {
                return 1;
            }
        }
    }

    return 1;
}


// This function check if the ip of the packet is the same as the ip of the rule.
int check_packet_ip(__be32 rule_ip, __be32 rule_prefix_mask, __u8 rule_prefix_size, __be32 packet_ip) {
    //printk("%d %d\n",rule_ip, packet_ip );
    __be32 rule_ip_network = rule_ip & rule_prefix_mask;
    __be32 packet_ip_network = packet_ip & rule_prefix_mask;
    return rule_ip_network == packet_ip_network;
}


// This function check if the port of the packet is the same as the port of the rule.
int check_packet_port(__be16 rule_port, __be16 packet_port) {
    if (rule_port == 0)
    {
        return 1;
    }
    if (rule_port == PORT_ABOVE_1023 && packet_port > 1023)
    {
        return 1;
    }
    return rule_port == packet_port;
}

int check_packet_ack(ack_t rule_ack, ack_t packet_ack) {
    if (rule_ack == ACK_ANY){
      return 1;
    }
    return rule_ack == packet_ack;
}

void print_log(log_row_t *log){
    printk("time: %d\n", log->timestamp);
    printk("protocol: %d\n", log->protocol);
    printk("action: %d\n", log->action);
    printk("src_ip: %d\n", log->src_ip);
    printk("dst_ip: %d\n", log->dst_ip);
    printk("src_port: %d\n", log->src_port);
    printk("dst_port: %d\n", log->dst_port);
    printk("reason: %d\n", log->reason);
    printk("count: %d\n", log->count);
}



/*
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;
*/
