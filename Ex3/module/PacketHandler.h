#ifndef _FILTER_H_
#define _FILTER_H_


#include "fw.h"
#include "PacketHandler.h"

// This function will be assign to the nf_hook_ops struct, and will be called on each packet that is going through the network.
unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// functions for extracting the packet fields
void set_direction(struct sk_buff *skb, direction_t *packet_direction, const struct nf_hook_state *state);
void set_src_dst_ip(struct sk_buff *skb, __be32 *packet_src_ip, __be32 *packet_dst_ip);
void set_src_dst_port(struct sk_buff *skb, __be16 *packet_src_port, __be16 *packet_dst_port);
void set_protocol(struct sk_buff *skb, __u8 *packet_protocol);
void set_ack_and_xmas(struct sk_buff *skb, ack_t *packet_ack, __u8 *is_XMAS_Packet);


// functions for checking the packet fields with the rule
int check_rule_for_packet(rule_t *rule, direction_t *packet_direction, __be32 *packet_src_ip, __be32 *packet_dst_ip, __u8 *packet_protocol, __be16 *packet_src_port, __be16 *packet_dst_port, ack_t *packet_ack);
int check_packet_port(__be16 packet_port, __be16 rule_port);
int check_packet_ip(__be32 rule_ip, __be32 rule_prefix_mask, __u8 rule_prefix_size, __be32 packet_ip);
int check_packet_ack(ack_t packet_ack, ack_t rule_ack);

void print_log(log_row_t *log);


#endif
