#include "fw.h"
#include "FWLogDevice.h"
#include "FWRuleDevice.h"
#include "PacketHandler.h"
#include "FWConnectionDevice.h"
#include "FWProxyDevice.h"

static int cnt = 0;



unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    packet_information_t packet;
    extract_information_from_packet(&packet, skb, state);
    print_packet(&packet.src_ip, &packet.dst_ip, &packet.src_port, &packet.dst_port, &packet.protocol, &packet.ack, &packet.direction, packet.syn);

    if(packet.hook == NF_INET_LOCAL_OUT){
        return Local_Out_Handler(&packet);
    }
    return Pre_Routing_Handler(&packet);
}

// This function will Handle Local_Out packets.
// Here we just need to change routing for packets that are part of a proxy connection.
// And we will return NF_ACCEPT.
unsigned int Local_Out_Handler(packet_information_t *packet){
    // if the packet is part of a proxy connection, we need to change the corresponding fields in the packet for the proxy.
    route_proxy_packet(packet);
    // after we changed (if needed) the routing we will accept the packet.
    return NF_ACCEPT;
    }


// This function will Handle Pre_Routing packets.
// The flow is:
// 1. Check for special cases.
// 2. check for proxy routing.
// 3. check for packet protocol:
// 3.1. If the packet is not TCP, perform stateless inspection.
// 3.2. If the packet is TCP:
// 3.2.1. If the packet is not part of a connection, check for syn and perform stateless inspection.
//        If the packet passed the stateless inspection, add new connection.
// 3.2.2. perform stateful inspection and change the state of the connection.
unsigned int Pre_Routing_Handler(packet_information_t *packet){
    log_row_t log_for_packet;
    set_time_ip_and_port_for_log(&log_for_packet, &(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), &(packet->protocol));
    connection_t *conn = is_connection_exist(&(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), packet->direction);
    if (conn == NULL){
        print_message("Connection is NULL\n"); // Debug
    }
    // We first need to check for special cases.
    int special = check_for_special_cases(packet);
    // if special is 1 it means the packet is allowed and we will accept it.
    if (special == 1){
        return NF_ACCEPT;
    }
    // if special is 0 it means the packet is not allowed and we will drop it.
    if (special == 0){
        add_log(&log_for_packet, REASON_XMAS_PACKET, NF_DROP);
        return NF_DROP;
    }

    // if the packet is not TCP we will perform stateless inspection.
    if (packet->protocol != PROT_TCP){
        return perform_stateless_inspection(packet, &log_for_packet, 1);
    }

    // if the packet is part of a proxy connection, we need to change the corresponding fields in the packet for the proxy.
    if (is_proxy_connection(packet, conn) == 1){
        print_message("Proxy Connection is used\n"); // Debug
        add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
        return NF_ACCEPT;
    }

    // if the packet is TCP, we need to check if the packet is part of a connection.
    if (conn == NULL){
        // if the packet is not part of a connection we need to check if it's a syn packet.
        if (packet->syn && packet->ack == ACK_NO){
            // if it is, we will perform stateless inspection.
            if (perform_stateless_inspection(packet, &log_for_packet, 0) == NF_DROP){
                // if the packet is not allowed we will drop it.
                return NF_DROP;
            }
            // if the packet is allowed, we will create connection and check for proxy.
            conn = insert_connection(&(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), packet->direction);
            
            if (create_proxy(packet, conn) == 1){
                print_message("Proxy Connection is created\n"); // Debug
                add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
                return NF_ACCEPT;
            }
        }
        else{ // If it's not a syn packet, we will drop it.
            add_log(&log_for_packet, REASON_NO_MATCHING_CONNECTION, NF_DROP);
            return NF_DROP;
        }
    }


    // Now, We do have a connection (even new packets has, with state of PRESYN).
    // We will perform stateful inspection.
    int TCP_validity = perform_statefull_inspection(packet, &conn->state);

    if (TCP_validity == 0){ // If the packet is invalid, we will drop it.
        add_log(&log_for_packet, REASON_INVALID_CONNECTION_STATE, NF_DROP);
        return NF_DROP;
    }
    if (TCP_validity == 2){ // If the connection is about to close, we will remove it.
        finish_connection(conn);
        add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
        return NF_ACCEPT;
    }
    if (TCP_validity == 1){ // If the packet is valid, we will accept it.
        add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
        return NF_ACCEPT;
    }
    return NF_DROP; // If we are here, it means the packet is not valid and we will drop it.
}




// This function will be the stateless part of the full firewall inspection.
// It will get the packet and check if it is valid according to the rules.
// It will return the action of the packet (accept or drop).
// It will also log the action of the packet.
int perform_stateless_inspection(packet_information_t *packet, log_row_t *log_for_packet, int log_action){
    rule_t *rule_table;
    int ind;
    connection_t *conn;
    // If the rule table is not valid, then accept automatically (and log the action).
    if (is_valid_table() == 0)
    {
        if (log_action == 1)
        {
            add_log(log_for_packet, REASON_FW_INACTIVE, NF_ACCEPT);
        }
        return NF_ACCEPT;
    }

    // now a we need to check if there is a rule that match to the packet.
    // We need to work based on the first rule matched to the packet.
    // if no rule is matched we need to drop the packet.

    rule_table = get_rule_table();
    for(ind = 0; ind < get_rules_amount(); ind++){
        if (check_rule_for_packet(rule_table + ind, &(packet->direction), &(packet->src_ip), &(packet->dst_ip), &(packet->protocol), &(packet->src_port), &(packet->dst_port), &(packet->ack))){
            // if we found a match we need to log the action and return the action.
            // when a rule match, the reason of the log will be the rule index.
            if (log_action == 1){
                add_log(log_for_packet, ind, (rule_table + ind)->action);
            }
            return (rule_table + ind)->action;
        }
    }
    // if no match found we log the action and return NF_DROP.
    if (log_action == 1){
        add_log(log_for_packet, REASON_NO_MATCHING_RULE, NF_DROP);
    }
    return NF_DROP;
}




// This function will get the packet info and check for special cases.
// The following cases are checked:
// 1. If the packet if LOOPBACK packet.
// 2. If the packet is not TCP, UDP or ICMP.
// 3. If the packet is destined to the firewall itself.
// 4. If the packet is not between the internal and external networks.
// The function return 1 for accept, 0 for drop and -1 if neither.
int check_for_special_cases(packet_information_t *packet){
    // if the packet is a loopback packet we will accept it without log
    if (((packet->src_ip & 0xFF000000) == 0x7F000000) || ((packet->dst_ip & 0xFF000000) == 0x7F000000)){
        return 1;
    }

    // if the packet is not TCP, UDP or ICMP we will accept it without log
    if (packet->protocol == PROT_OTHER){
        // if packet_protocol is -1 it means the protocol is not TCP, UDP or ICMP and we will accept it
        return 1;
    }

    // if the packet is destined to the firewall itself we will accept it without log
    // we can do so by checking if the packet is destined to the internal or external ip of the firewall.
    // which are 167837955 ( 10.1.1.3) and 167838211 (10.1.2.3).
    if ((packet->dst_ip == FW_IN_LEG) || (packet->src_ip == FW_OUT_LEG)){
        return 1;
    }

    // if the packet is not between the internal and external networks we will drop it.
    if (packet->direction == DIRECTION_NONE){
        return 1;
    }
    // if the packet is XMAS packet we should log and drop it.
    if (packet->XMAS){    
        return 0;
    }
    return -1;
}



// This function will do the stateful inspection for a TCP packet.
// It will use a TCP state machine to check if the packet is valid.
// If the packet is valid it will return 1 and update the state to the next state.
// if the packet is not valid it will return 0.
// If the packet is valid, and the connection is about to close, it will return 2.

int perform_statefull_inspection(packet_information_t *packet, tcp_state_t *state)
{   
    const struct tcphdr *tcph = tcp_hdr(packet->skb);
    direction_t packet_direction = packet->direction;
    tcp_status_t status = state->status;
    direction_t conn_direction = state->direction;

    // we first need to check if the packet is in the right direction.
    // if the packet is not in the right direction we will return 1.
    if (packet_direction != conn_direction && conn_direction != DIRECTION_ANY){
        print_message("unexpected direction\n");
        return 0;
    }
    if (status == INIT){
        if (tcph->syn && !tcph->ack){
            state->status = SYN;
            state->direction = packet_direction;
            return 1;
        }
        return 0;
    }
    // If we are here it means that the packet is in the right direction!
    // Now its time for the state machine.
    // Further information about the state machine can be found in the documentation.
    // The state machine is based on the only options a packet can do in a TCP connection while on specific state.

    // if the state is SYN, it means we expect a syn-ack packet from the other side.
    if (status == SYN){
        //printk("At SYN: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->syn && tcph->ack){
            state->status = SYN_ACK;
            state->direction = next_direction(packet_direction);
            return 1;
        }
        return 0;

    }

    // if the state is SYN_ACK, it means we expect an ack packet to establish the connection.
    // since the connection is just established we don't have a specific direction to expect.
    if (status == SYN_ACK){
        //printk("At SYN_ack: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->ack){
            state->status = ESTABLISHED;
            state->direction = DIRECTION_ANY;
            return 1;
        }
        return 0;
    }

    // at this state, it means the connection is established and we can accept any packet from any direction.
    // if the packet is a fin packet, it means the connection is about to close.
    // at this point we need to change the state to FIN1 and expect a fin-ack packet from the other side.
    if (status == ESTABLISHED){
        //printk("At ESTABLISHED: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->fin){
            state->status = A_SENT_FIN;
            state->direction = next_direction(packet_direction);
            return 1;
        }
        return 1;
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
        //printk("At A_SENT_FIN: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->ack){
            state->status = A_FIN_B_ACK;
            state->direction = packet_direction;
            return 1;
        }
        if (tcph->fin){
            state->status = A_FIN_B_FIN;
            state->direction = DIRECTION_ANY;
            return 1;
        }
        if (tcph->fin && tcph->ack){
            state->status = A_FIN_B_FIN_ACK;
            state->direction = next_direction(packet_direction);
            return 1;
        }
        return 1;
    }

    // if the state is A_FIN_B_ACK, it means we expect a fin packet.
    // if the packet is a fin packet, it means the connection is about to close and we need to expect an ack packet from the other side.
    // so we move to the state A_FIN_B_FIN_ACK.
    if (status == A_FIN_B_ACK){
        //printk("At A_FIN_B_ACK: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->fin){
            state->status = A_FIN_B_FIN_ACK;
            state->direction = DIRECTION_ANY;
            return 1;
        }
        return 1;
    }

    // if the state is A_FIN_B_FIN_ACK, it means we expect an ack packet that will close the connection.
    // so we need to check if the packet is an ack packet and return 2.
    if (status == A_FIN_B_FIN_ACK){
        //printk("At A_FIN_B_FIN_ACK: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->ack){
            return 2;
        }
        return 0;
    }

    // if the state is A_FIN_B_FIN, it means we need ack from every side to close the connection.
    // so we need to check if the packet is an ack packet and update the state to be A_FIN_B_FIN_ACK.
    if (status == A_FIN_B_FIN){
        //printk("At A_FIN_B_FIN: syn: %d, ack: %d, fin: %d\n", tcph->syn, tcph->ack, tcph->fin);
        if (tcph->ack){
            state->status = A_FIN_B_FIN_ACK;
            state->direction = next_direction(packet_direction);
            return 1;
        }
        return 0;
    }
    return 0;
}


// This function will extract the information from the skb to the packet_information_t struct.
void extract_information_from_packet(packet_information_t *packet, struct sk_buff *skb, const struct nf_hook_state *state){
    set_direction(skb, &packet->direction, state);
    set_src_dst_ip(skb, &packet->src_ip, &packet->dst_ip);
    set_src_dst_port(skb, &packet->src_port, &packet->dst_port);
    set_protocol(skb, &packet->protocol);
    packet->hook = state->hook;
    packet->skb = skb;
    packet->state = state;
    // if the packet is tcp, we need to add the field: syn, ack, fin, XMAS.
    if (packet->protocol == PROT_TCP){
        struct tcphdr *tcph = tcp_hdr(skb);
        set_xmas(&packet->XMAS, tcph);
        packet->syn = tcph->syn;
        packet->ack = tcph->ack ? ACK_YES : ACK_NO;
        packet->fin = tcph->fin;
    }
    else{
        packet->syn = 0;
        packet->ack = ACK_NO;
        packet->fin = 0;
    }
}





// This function get a packet and extract the direction from it and store it in the packet_direction.
void set_direction(struct sk_buff *skb, direction_t *packet_direction, const struct nf_hook_state *state) {
    
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

void set_xmas(__u8 *is_XMAS_Packet, struct tcphdr *tcph){
    if (tcph->fin && tcph->urg && tcph->psh)
    {
        *is_XMAS_Packet = 1;
        return;
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



//   ------------------------------- DEBUGGING FUNCTIONS -------------------------------


// This function used for debugging.
// It will print the log information if the debug flag is 1.
void print_log(log_row_t *log){
    if (DEBUG == 0){
        return;
    }
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
// This function used for debugging.
// It will print the packet information if the debug flag is 1.
void print_packet(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, __u8 *protocol, ack_t *ack, direction_t *direction, unsigned int is_syn_packet){
    if (DEBUG == 0){
        return;
    }
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

// This function used for debugging.
// It will print a messege if the debug flag is 1.
void print_message(char *messege){
    if (DEBUG == 0){
        return;
    }
    printk("%s\n", messege);
}