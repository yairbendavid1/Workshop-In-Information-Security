#include "filter.h"
#include "fw.h"

// This function is called when a packet is received at one of the hook points.
static unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // Allocate firewall structs
    packet_t packet;
    log_row_t log_row;

    // Get the head of the rule table, and iterate over the rules
    // Note that we aren't supposed to change the rules here, hence the const keyword
    const rule_t *const rules = get_rules();
    const rule_t *rule;
    __u8 rule_index;

    // Get the required packet fields. The fields should not be changed throughout the filtering.
    parse_packet(&packet, skb, state);

    // Get the log_row fields from the packet
    get_log_row(&packet, &log_row);

    // Special actions: (depending on the packet's type)
    switch (packet.type)
    {
    case PACKET_TYPE_LOOPBACK:
        return NF_ACCEPT; // Accept any loopback (
}