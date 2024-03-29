#ifndef _HANDLER_H_
#define _HANDLER_H_


#include "fw.h"
#include "PacketHandler.h"
#include "FWConnectionDevice.h"

#define INT_NET_DEVICE_NAME "enp0s8"
#define EXT_NET_DEVICE_NAME "enp0s9"
#define FW_IN_LEG 167837955
#define FW_OUT_LEG 167838211

typedef struct
{
    direction_t direction;
    unsigned int hook;
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port; // number of port or 0 for any or port 1023 for any port number > 1023
    __be16 dst_port; // number of port or 0 for any or port 1023 for any port number > 1023
   __u8 XMAS;
    __u8 syn;
    __u8 fin;
    __u8 protocol;   // values from: prot_t
    ack_t ack;       // values from: ack_t
    packet_type_t type;
} packet_information_t;

// This function will be assign to the nf_hook_ops struct, and will be called on each packet that is going through the network.
unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int perform_statefull_inspection(packet_information_t *packet, tcp_state_t *state);
int perform_stateless_inspection(packet_information_t *packet, log_row_t *log_for_packet, int log_action);
int Handle_Proxy_Packet(packet_information_t *packet);

// functions for extracting the packet fields
void extract_information_from_packet(packet_information_t *packet *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void set_direction(struct sk_buff *skb, direction_t *packet_direction, const struct nf_hook_state *state);
void set_src_dst_ip(struct sk_buff *skb, __be32 *packet_src_ip, __be32 *packet_dst_ip);
void set_src_dst_port(struct sk_buff *skb, __be16 *packet_src_port, __be16 *packet_dst_port);
void set_protocol(struct sk_buff *skb, __u8 *packet_protocol);
void set_ack_and_xmas(struct sk_buff *skb, ack_t *packet_ack, __u8 *is_XMAS_Packet);
void set_xmas(__u8 *is_XMAS_Packet, struct tcphdr *tcph);


// functions for checking the packet fields with the rule
int check_rule_for_packet(rule_t *rule, direction_t *packet_direction, __be32 *packet_src_ip, __be32 *packet_dst_ip, __u8 *packet_protocol, __be16 *packet_src_port, __be16 *packet_dst_port, ack_t *packet_ack);
int check_packet_port(__be16 packet_port, __be16 rule_port);
int check_packet_ip(__be32 rule_ip, __be32 rule_prefix_mask, __u8 rule_prefix_size, __be32 packet_ip);
int check_packet_ack(ack_t packet_ack, ack_t rule_ack);
int check_for_special_cases(packet_information_t *packet);
void print_log(log_row_t *log);
void print_packet(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, __u8 *protocol, ack_t *ack, direction_t *direction, unsigned int is_syn_packet);


#endif
