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
            }
        }
        else{ // If it's not a syn packet, we will drop it.
            add_log(&log_for_packet, REASON_NO_MATCHING_CONNECTION, NF_DROP);
            return NF_DROP;
        }
    }

    // if the packet is part of a proxy connection, we need to change the corresponding fields in the packet for the proxy.
    if (is_proxy_connection(packet, conn) == 1){
        add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
        return NF_ACCEPT;
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

/*

// This function will Handle Pre_Routing packets.
// The flow is:
// 1. Check for special cases.
// 2. check for packet protocol:
// 2.1. If the packet is not TCP, perform stateless inspection.
// 2.2. If the packet is TCP, check connection table:
// 2.2.1. If connection exist, perform stateful inspection with Proxy Checking.
// 2.2.2. If connection doesn't exist, check for syn and perform stateless inspection with Proxy Checking.
// unsigned int Pre_Routing_Handler(packet_information_t *packet){
//     // We first need to check for special cases.
//     log_row_t log_for_packet;
//     int special = check_for_special_cases(packet);
//     set_time_ip_and_port_for_log(&log_for_packet, &(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), &(packet->protocol));
//     // if special is 1 it means the packet is allowed and we will accept it.
//     if (special == 1){
//         return NF_ACCEPT;
//     }
//     // if special is 0 it means the packet is not allowed and we will drop it.
//     if (special == 0){
//         add_log(&log_for_packet, REASON_XMAS_PACKET, NF_DROP);
//         return NF_DROP;
//     }
//     // Now, we need to check if the packet is TCP or not.
//     // if the packet is not TCP we will perform stateless inspection.
//     if (packet->protocol != PROT_TCP){
//         return perform_stateless_inspection(packet, &log_for_packet, 1);
//     }

//     // In case of TCP, we need to check if the packet is already part of a connection.
//     connection_t *conn = is_connection_exist(&(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), packet->direction);
    
    
//     if (conn == NULL){
//         // If it doesn't, we need to check if it's a syn packet.
//         if (packet->syn && packet->ack == ACK_NO){
//             // If it is, we will perform stateless inspection.
//             if (perform_stateless_inspection(packet, &log_for_packet, 0) == NF_DROP){
//                 return NF_DROP;
//             }
//             // If the packet is allowed, we need to check for proxy and add new connection respectively.

//             conn = insert_connection(&(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), packet->direction);
//             if (Handle_Proxy_Packet(packet) == 1){
//                 add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
//                 return NF_ACCEPT;
//             }
//             add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
//             return NF_ACCEPT;
//         }
//         else{ // If it's not a syn packet, we will drop it.
//             add_log(&log_for_packet, REASON_NO_MATCHING_CONNECTION, NF_DROP);
//             return NF_DROP;
//         }
//     }
//     // If the packet is part of a connection, we will perform stateful inspection.
//     // If the packet is valid, we will accept it, while checking for proxy.

//     int TCP_validity = perform_statefull_inspection(packet, &conn->state);
//     if (TCP_validity == 0){
//         add_log(&log_for_packet, REASON_INVALID_CONNECTION_STATE, NF_DROP);
//         return NF_DROP;
//     }
//     if (TCP_validity == 2){
//         finish_connection(conn);
//         if(Handle_Proxy_Packet(packet) == 1){
//             add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
//             return NF_ACCEPT;
//         }
//         add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
//         return NF_ACCEPT;
//     }
//     if(Handle_Proxy_Packet(packet) == 1){
//         add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
//         return NF_ACCEPT;
//     }
//     add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
//     return NF_ACCEPT;

// }





// // This function is called when a packet is received at one of the hook points.
// unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
//     log_row_t log_for_packet;
//     packet_information_t *packet;
//     extract_information_from_packet(packet, skb, state);


//     // First we need to allocate some memory for the fields of the packet that store in the sk_buff.
//     // we will use those fields to check if the packet is allowed or not.
//     // direction_t packet_direction; // the direction of the packet
//     // __be32 packet_src_ip; // the source ip of the packet
//     // __be32 packet_dst_ip; // the destination ip of the packet
//     // __be16 packet_src_port; // the source port of the packet
//     // __be16 packet_dst_port; // the destination port of the packet
//     // __u8 packet_protocol; // the protocol of the packet
//     // ack_t packet_ack; // the ack of the packet
//     // __u8 is_XMAS_Packet; // bit that indicate if the packet is XMAS packet
//     // unsigned int is_syn_packet = check_for_syn_packet(skb, state); // bit that indicate if the packet is a syn packet
//     connection_t *conn;
//     __u8 TCP_validity;
//     rule_t *rule_table;
//     int special;

//     // Now we will parse the packet and fill the fields with the values from the packet.
//     // set_direction(skb, &packet_direction, state);
//     // set_src_dst_ip(skb, &packet_src_ip, &packet_dst_ip);
//     // set_src_dst_port(skb, &packet_src_port, &packet_dst_port);
//     // set_protocol(skb, &packet_protocol);
//     // set_ack_and_xmas(skb, &packet_ack, &is_XMAS_Packet);

//     // we need to check if one of the special cases is valid for the packet.
//     special = check_for_special_cases(packet);
//     if (special == 1){
//         return NF_ACCEPT;
//     }
//     if (special == 0){
//         set_time_ip_and_port_for_log(&log_for_packet, &(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), &(packet->protocol));
//         add_log(&log_for_packet, REASON_XMAS_PACKET, NF_DROP);
//         return NF_DROP;
//     }


//     // as now, we can fill the time, ip port and protocol fields of the log_row_t struct.
//     // reason, action and count will be filled later.
//     set_time_ip_and_port_for_log(&log_for_packet, &(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), &(packet->protocol));


//     // we need to check for XMAS packet
//     if(is_XMAS_Packet){
//         add_log(&log_for_packet, REASON_XMAS_PACKET, NF_DROP);
//         return NF_DROP;
//     }

//     // if the packet is part of a proxy connection, we need to change the corresponding fields in the packet for the proxy.
//     if (Handle_Proxy_Packet(packet) == 1){
//         add_log(&log_for_packet, REASON_PROXY, NF_ACCEPT);
//         return NF_ACCEPT;
//     }

//     if(packet->hook == NF_INET_LOCAL_OUT){
//         return NF_ACCEPT;
//     }

//     //print_packet(&packet_src_ip, &packet_dst_ip, &packet_src_port, &packet_dst_port, &packet_protocol, &packet_ack, &packet_direction, is_syn_packet);


//     // Stateful Part
    
//     // If the packet is TCP and not a syn packet, we need to check if the packet is part of an existing connection.
//     if (packet->protocol == PROT_TCP && !(packet->syn == 1 && packet->ack == 0)){
//         // if the packet is not a syn packet we need to check if the packet is part of an existing connection.

//         // if the packet is not part of an existing connection we will drop it and log the action.
//         conn = is_connection_exist(&(packet->src_ip), &(packet->dst_ip), &(packet->src_port), &(packet->dst_port), packet->direction);
//         if (conn == NULL){
//             add_log(&log_for_packet, REASON_NO_MATCHING_CONNECTION, NF_DROP);
//             return NF_DROP;
//         }

//         // if the packet is part of an existing connection we will perform stateful inspection.

//         TCP_validity = perform_statefull_inspection(packet, &conn->state);
//         //printk("TCP_validity: %d\n", TCP_validity);

//         // if TCP_validity is 0 it means the packet is valid and we will accept it.
//         // if TCP_validity is 1 it means the packet is not valid and we will drop it.
//         // if TCP_validity is 2 it means the packet is valid and the connection is about to close so we will remove it from the connection table.
//         if(TCP_validity == 0){
//             add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
//             return NF_ACCEPT;
//         }
//         if(TCP_validity == 1){
//             add_log(&log_for_packet, REASON_INVALID_CONNECTION_STATE, NF_DROP);
//             return NF_DROP;
//         }
//         if(TCP_validity == 2){
//             finish_connection(conn);
//             add_log(&log_for_packet, REASON_VALID_CONNECTION_EXIST, NF_ACCEPT);
//             return NF_ACCEPT;
//         }
//         return NF_DROP;
    
//     }
//     // if the packet is not TCP or it is a syn packet we will perform stateless inspection.
//     // Stateless Part
//     return perform_stateless_inspection(skb, state, &log_for_packet, packet_direction, packet_src_ip, packet_dst_ip, packet_protocol, packet_src_port, packet_dst_port, packet_ack, is_syn_packet, 1);

// }



*/


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

// This function will Handle the packet if it is part of a proxy connection.
// In order to check if a packet is a part of proxy, we need to check the direction, ip port and the hook type.
// There are 4 types of proxy connections:
// 1. client send to the server - we need to hook the packet at the prerouting point and change the destination ip and port to the FW.
// 2. server send to the client - we need to hook the packet at the prerouting point and change the source ip and port to the FW.
// 3. FW to client - we need to hook the packet at the localout point and change the source ip and port to the server.
// 4. FW to server - we need to hook the packet at the localout point and change the destination ip and port to the client.
// If the packet is part of a proxy connection we will change the corresponding fields in the packet and return 1.
// If the packet is not part of a proxy connection we will return 0 (and then continue the regular inspection).
// int Handle_Proxy_Packet(packet_information_t *packet){
//     // Proxy Packets are all TCP packets:
//     if (packet->protocol != PROT_TCP){
//         return 0;
//     }
//     struct sk_buff *skb = packet->skb;
//     struct iphdr *iph = ip_hdr(skb);
//     struct tcphdr *tcph = tcp_hdr(skb);
//     connection_t *conn;
//     __be16 fw_port;
//     if (packet->direction== DIRECTION_OUT){ 
//         // if the packet it destined to the outside, it means there are 2 options:
//         // 1. the packet is from the client to the server.
//         // 2. the packet is from the FW to the server.
//         // we can check it by check the hook type.
//         if (packet->hook == NF_INET_PRE_ROUTING){
//             // if the hook type is prerouting it means the packet is from the client to the server.
//             // so we need to check if the packet in the connection table.
//             // and if so, we need to change the destination ip and port to the FW.
//             // if the packet is not in the connection table we will return 0.
//             conn = from_client_to_proxy_connection(&(packet->src_ip), &(packet->src_port));
//             if (conn == NULL){
//                 return 0;
//             }
//             // we also need to check that the packet is indeed need to be proxied.
//             if(packet->dst_port != 80 && packet->dst_port != 21){
//                 return 0;
//             }
//             // Change the routing
//                 iph->daddr = htonl(FW_IN_LEG);
//                 if (conn->proxy.proxy_state == REG_HTTP){
//                     fw_port = 800;
//                 }
//                 else{
//                     fw_port = 210;
//                 }
//                 tcph->dest = htons(fw_port);

//                 // Fix the checksum
//                 fix_checksum(skb);
//                 printk("packet is proxied in client to FW\n");
//                 return 1;

//         }
//         else{
//             // if the hook type is localout it means the packet is from the FW to the server.
//             // so we need to check if the source port is in the FW proxy ports.
//             // and if so, we need to change the source ip to be the client.

            
//             conn = is_port_proxy_exist(&(packet->src_port));
//             if (conn == NULL){
//                 return 0;
//             }
            
//             // we also need to check if the packet is destined for the server.
//             if (packet->dst_ip != conn->outity.ip || packet->dst_port != conn->outity.port){
//                 return 0;
//             }
//             // Fake source
//             iph->saddr = (conn->intity.ip);

//             // Fix the checksum
//             fix_checksum(skb);
//             printk("packet is proxied in FW to Server\n");
//             return 1;
//         }
//     }
//     else{
//         // if the packet is destined to the inside, it means there are 2 options:
//         // 1. the packet is from the server to the client.
//         // 2. the packet is from the FW to the client.
//         // we can check it by check the hook type.
//         if (packet->hook == NF_INET_LOCAL_OUT){
//             // if the hook type is local out it means the packet is from the fw to the client.
//             // so we need to check if the packet in the connection table.
//             // and if so, we need to change the source ip and port to the FW.
//             // if the packet is not in the connection table we will return 0.
//             conn = from_client_to_proxy_connection(&(packet->dst_ip), &(packet->dst_port));
//             if (conn == NULL){
//                 return 0;
//             }
            
//             // fake the source
//             iph->saddr = (conn->outity.ip);
//             tcph->source = htons(conn->outity.port);

//             // Fix the checksum
//             fix_checksum(skb);
//             printk("packet is proxied in FW to Client\n");
//             return 1;
//         }
//         else{
//             // if the hook type is pre routing it means the packet is from the server to the client.
//             // so we need to check if the dst port is in the FW proxy ports.
//             // and if so, we need to change the dst ip to be the FW.
//             conn = is_port_proxy_exist(&(packet->dst_port));
//             if (conn == NULL){
//                 return 0;
//             }
            
//             // we also need to check if the packet is from the server in the connection table.
//             if (packet->src_ip != conn->outity.ip || packet->src_port != conn->outity.port){
//                 return 0;
//             }
//             //change the routing
//             iph->daddr = htonl(FW_OUT_LEG);

//             // Fix the checksum
//             fix_checksum(skb);
//             printk("packet is proxied in server to FW\n");
//             return 1;
        

//         }
//     }
//     return 0;
// }





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



