#ifndef _FILTER_H_
#define _FILTER_H_


#include "fw.h"
#include "rule.h"

unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif