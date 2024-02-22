#include "fw.h"
#include "FWLogDevice.h"
#include "FWRuleDevice.h"
#include "PacketHandler.h"
#include "FWConnectionDevice.h"

static int cnt = 0;

// This function is called when a packet is received at one of the hook points.
unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
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
    unsigned int is_syn_packet = check_for_syn_packet(skb, state); // bit that indicate if the packet is a syn packet
    connection_t *conn;
    __u8 TCP_validity;
    rule_t *rule_table;
    int special;

    // Now we will parse the packet and fill the fields with the values from the packet.
    set_direction(skb, &packet_direction, state);
    set_src_dst_ip(skb, &packet_src_ip, &packet_dst_ip);
    set_src_dst_port(skb, &packet_src_port, &packet_dst_port);
    set_protocol(skb, &packet_protocol);
    set_ack_and_xmas(skb, &packet_ack, &is_XMAS_Packet);

    // we need to check if one of the special cases is valid for the packet.
    special = check_for_special_cases(&packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, &packet_protocol, &packet_direction);
    if (special == 1){
        return NF_ACCEPT;
    }


    // as now, we can fill the time, ip port and protocol fields of the log_row_t struct.
    // reason, action and count will be filled later.
    set_time_ip_and_port_for_log(&log_for_packet, &packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, &packet_protocol);


    // we need to check for XMAS packet
    if(is_XMAS_Packet){
        add_log(&log_for_packet, REASON_XMAS_PACKET, NF_DROP);
        return NF_DROP;
    }


    print_packet(&packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, &packet_protocol, &packet_ack, &packet_direction, is_syn_packet);
    // Stateful Part
    
    // If the packet is TCP and not a syn packet, we need to check if the packet is part of an existing connection.
    if (packet_protocol == PROT_TCP && !is_syn_packet){
        // if the packet is not a syn packet we need to check if the packet is part of an existing connection.

        // if the packet is not part of an existing connection we will drop it and log the action.
        conn = is_connection_exist(&packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, packet_direction);
        if (conn == NULL){
            add_log(&log_for_packet, REASON_NO_MATCHING_CONNECTION, NF_DROP);
            return NF_DROP;
        }

        // if the packet is part of an existing connection we will perform stateful inspection.

        TCP_validity = perform_statefull_inspection(tcp_hdr(skb), packet_direction, &conn->state);
        printk("TCP_validity: %d\n", TCP_validity);

        // if TCP_validity is 0 it means the packet is valid and we will accept it.
        // if TCP_validity is 1 it means the packet is not valid and we will drop it.
        // if TCP_validity is 2 it means the packet is valid and the connection is about to close so we will remove it from the connection table.
        if(TCP_validity == 0){
            add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
            return NF_ACCEPT;
        }
        if(TCP_validity == 1){
            add_log(&log_for_packet, REASON_INVALID_CONNECTION_STATE, NF_DROP);
            return NF_DROP;
        }
        if(TCP_validity == 2){
            finish_connection(conn);
            add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
            return NF_ACCEPT;
        }
        return NF_DROP;
    
    }
    // if the packet is not TCP or it is a syn packet we will perform stateless inspection.
    // Stateless Part


    // If the rule table is not valid, then accept automatically (and log the action).
    if (is_valid_table() == 0)
    {

        add_log(&log_for_packet, REASON_FW_INACTIVE, NF_ACCEPT);
        return NF_ACCEPT;
    }

    // now after we cover all the side cases we need to check if there is a rule that match to the packet.
    // We need to work based on the first rule matched to the packet.
    // if no rule is matched we need to drop the packet.

    rule_table = get_rule_table();
    int ind;
    for(ind = 0; ind < get_rules_amount(); ind++){
        if (check_rule_for_packet(rule_table + ind, &packet_direction, &packet_src_ip, &packet_dst_ip, &packet_protocol, &packet_src_port, &packet_dst_port, &packet_ack)){
            // if we found a match we need to log the action and return the action.
            // when a rule match, the reason of the log will be the rule index.

            // if the packet is a syn packet we need to add a new connection to the connection table.
            if (packet_protocol == PROT_TCP && is_syn_packet){
                printk("inserting connection");
                insert_connection(&packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, packet_direction);
            }
            add_log(&log_for_packet, ind, (rule_table + ind)->action);
            return (rule_table + ind)->action;
        }
    }
    // if no match found we log the action and return NF_DROP.
    add_log(&log_for_packet, REASON_NO_MATCHING_RULE, NF_DROP);
    return NF_DROP;

}

// This function will get the packet info and check for special cases.
// The following cases are checked:
// 1. If the packet if LOOPBACK packet.
// 2. If the packet is not TCP, UDP or ICMP.
// 3. If the packet is destined to the firewall itself.
// 4. If the packet is not between the internal and external networks.
// The function return 1 for accept, 0 for drop and -1 if neither.
int check_for_special_cases(__be32 *packet_src_ip, __be32 *packet_dst_ip, __be16 *packet_src_port, __be16 *packet_dst_port, __u8 *packet_protocol, direction_t *packet_direction){
    // if the packet is a loopback packet we will accept it without log
    if (((*packet_src_ip & 0xFF000000) == 0x7F000000) || ((*packet_dst_ip & 0xFF000000) == 0x7F000000)){
        return 1;
    }

    // if the packet is not TCP, UDP or ICMP we will accept it without log
    if (*packet_protocol == PROT_OTHER){
        // if packet_protocol is -1 it means the protocol is not TCP, UDP or ICMP and we will accept it
        return 1;
    }

    // if the packet is destined to the firewall itself we will accept it without log
    // we can do so by checking if the packet is destined to the internal or external ip of the firewall.
    // which are 167837955 ( 10.1.1.3) and 167838211 (10.1.2.3).
    if ((*packet_dst_ip == 167837955) || (*packet_dst_ip == 167838211)){
        return 1;
    }

    // if the packet is not between the internal and external networks we will drop it and log the action.
    if (*packet_direction == DIRECTION_NONE){
        return 1;
    }

    return -1;
}



// This function will do the stateful inspection for a TCP packet.
// It will use a TCP state machine to check if the packet is valid.
// If the packet is valid it will return 0 and update the state to the next state.
// if the packet is not valid it will return 1.
// If the packet is valid, and the connection is about to close, it will return 2.

int perform_statefull_inspection(const struct tcphdr *tcph, direction_t packet_direction, tcp_state_t *state)
{
    tcp_status_t status = state->status;
    direction_t conn_direction = state->direction;

    // we first need to check if the packet is in the right direction.
    // if the packet is not in the right direction we will return 1.
    if (packet_direction != conn_direction && conn_direction != DIRECTION_ANY){
        printk("unexpected direction\n");
        return 1;
    }

    // If we are here it means that the packet is in the right direction!
    // Now its time for the state machine.
    // Further information about the state machine can be found in the documentation.
    // The state machine is based on the only options a packet can do in a TCP connection while on specific state.

    // if the state is SYN, it means we expect a syn-ack packet from the other side.
    if (status == SYN){
        printk("At SYN: syn: %d, ack: %d\n", tcph->syn, tcph->ack);
        if (tcph->syn && tcph->ack){
            state->status = SYN_ACK;
            state->direction = next_direction(packet_direction);
            return 0;
        }
        return 1;

    }

    // if the state is SYN_ACK, it means we expect an ack packet to establish the connection.
    // since the connection is just established we don't have a specific direction to expect.
    if (status == SYN_ACK){
        if (tcph->ack){
            state->status = ESTABLISHED;
            state->direction = DIRECTION_ANY;
            return 0;
        }
        return 1;
    }

    // at this state, it means the connection is established and we can accept any packet from any direction.
    // if the packet is a fin packet, it means the connection is about to close.
    // at this point we need to change the state to FIN1 and expect a fin-ack packet from the other side.
    if (status == ESTABLISHED){
        if (tcph->fin){
            state->status = A_SENT_FIN;
            state->direction = next_direction(packet_direction);
            return 0;
        }
        return 0;
    }

    // if the state is A_SENT_FIN, it means we expect a fin-ack packet.
    // but, it doesn't mean B can't send an ack or a fin packet. (B is the current sender side of the connection, and it can happen when the last packet has not arrived yet for example)
    // So, we need to check if the packet is an ack packet or a fin packet and update the state accordingly.
    // If the packet is an ack packet, we still need to expect a fin packet from B.
    // So in this case, we will move to the state A_FIN_B_ACK, while the expected direction will be the direction of the packet.
    // If the packet is a fin packet, it means the connection is about to close, but independently of the FIN of A,
    // which means, we need to expect a ack packet from any side.
    // If the packet is FIN and ACK, we need to expect a ACK from A, so we will move to the state A_FIN_B_FIN_ACK.
    if (status == A_SENT_FIN){
        if (tcph->ack){
            state->status = A_FIN_B_ACK;
            state->direction = packet_direction;
            return 0;
        }
        if (tcph->fin){
            state->status = A_FIN_B_FIN;
            state->direction = DIRECTION_ANY;
            return 0;
        }
        if (tcph->fin && tcph->ack){
            state->status = A_FIN_B_FIN_ACK;
            state->direction = next_direction(packet_direction);
            return 0;
        }
        return 1;
    }

    // if the state is A_FIN_B_ACK, it means we expect a fin packet.
    // if the packet is a fin packet, it means the connection is about to close and we need to expect an ack packet from the other side.
    // so we move to the state A_FIN_B_FIN_ACK.
    if (status == A_FIN_B_ACK){
        if (tcph->fin){
            state->status = A_FIN_B_FIN_ACK;
            state->direction = DIRECTION_ANY;
            return 0;
        }
        return 1;
    }

    // if the state is A_FIN_B_FIN_ACK, it means we expect an ack packet that will close the connection.
    // so we need to check if the packet is an ack packet and return 2.
    if (status == A_FIN_B_FIN_ACK){
        if (tcph->ack){
            return 2;
        }
        return 1;
    }

    // if the state is A_FIN_B_FIN, it means we need ack from every side to close the connection.
    // so we need to check if the packet is an ack packet and update the state to be A_FIN_B_FIN_ACK.
    if (status == A_FIN_B_FIN){
        if (tcph->ack){
            state->status = A_FIN_B_FIN_ACK;
            state->direction = next_direction(packet_direction);
            return 0;
        }
        return 1;
    }
    return 1;
}

// This function get a packet and extract the direction from it and store it in the packet_direction.
void set_direction(struct sk_buff *skb, direction_t *packet_direction, const struct nf_hook_state *state) {
    // char * in_device_name = state->in->name;
    // char * out_device_name = state->out->name;
    // if(strcmp(in_device_name, IN_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, OUT_NET_DEVICE_NAME) == 0) { // if the packet is coming from inside to outside
    //     *packet_direction = DIRECTION_OUT;
    //     return;
    //   }
    // if(strcmp(in_device_name, OUT_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, IN_NET_DEVICE_NAME) == 0) { // if the packet is coming from outside to inside
    //     *packet_direction = DIRECTION_IN;
    //     return;
    // }
    // *packet_direction = 0;

    char *net_in = state->in->name;
    char *net_out = state->out->name;

    if ((net_out != NULL && strcmp(net_out, EXT_NET_DEVICE_NAME) == 0) || (net_in != NULL && strcmp(net_in, INT_NET_DEVICE_NAME) == 0))
    {
        *packet_direction = DIRECTION_OUT; // Coming from inside to outside = direction out
        return;
    }
    if ((net_out != NULL && strcmp(net_out, INT_NET_DEVICE_NAME) == 0) || (net_in != NULL && strcmp(net_in, EXT_NET_DEVICE_NAME) == 0))
    {
        *packet_direction = DIRECTION_IN; // Coming from outside to inside = direction in
        return;
    }
    *packet_direction = DIRECTION_NONE;
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

        return 0;
    }

    // Check if the src ip is the same
    if (!check_packet_ip(rule->src_ip, rule->src_prefix_mask, rule->src_prefix_size, *packet_src_ip))
    {

        return 0;
    }

    // Check if the dst ip is the same
    if (!check_packet_ip(rule->dst_ip, rule->dst_prefix_mask, rule->dst_prefix_size, *packet_dst_ip))
    {

        return 0;
    }


    // Check if the protocol is the same
    if (rule->protocol != PROT_ANY && rule->protocol != *packet_protocol)
    {

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

            return 0;
        }
        if (!check_packet_port(rule->dst_port, *packet_dst_port))
        {

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
    if (rule_ip == 0)
    {
        return 1;
    }
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

void print_packet(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, __u8 *protocol, ack_t *ack, direction_t *direction, unsigned int is_syn_packet){
    printk("Packet number: %d\n", cnt++);
    printk("src_ip: %d\t", *src_ip);
    printk("dst_ip: %d\t", *dst_ip);
    printk("src_port: %d\t", *src_port);
    printk("dst_port: %d\t", *dst_port);
    printk("protocol: %d\t", *protocol);
    printk("ack: %d\t", *ack);
    printk("SYN: %d\t", is_syn_packet);
    printk("direction: %d\n", *direction);
}