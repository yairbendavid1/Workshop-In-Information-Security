#include "fw.h"
#include "PacketHandler.h"
#include "FWConnectionDevice.h"
#include "FWRuleDevice.h"
#include "FWProxyDevice.h"
#include "FWLogDevice.h"


// //   ------------------------------- DEBUGGING FUNCTIONS -------------------------------


// // This function used for debugging.
// // It will print the log information if the debug flag is 1.
// void print_log(log_row_t *log){
//     if (DEBUG == 0){
//         return;
//     }
//     printk("time: %d\n", log->timestamp);
//     printk("protocol: %d\n", log->protocol);
//     printk("action: %d\n", log->action);
//     printk("src_ip: %d\n", log->src_ip);
//     printk("dst_ip: %d\n", log->dst_ip);
//     printk("src_port: %d\n", log->src_port);
//     printk("dst_port: %d\n", log->dst_port);
//     printk("reason: %d\n", log->reason);
//     printk("count: %d\n", log->count);
// }
// // This function used for debugging.
// // It will print the packet information if the debug flag is 1.
// void print_packet(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, __u8 *protocol, ack_t *ack, direction_t *direction, unsigned int is_syn_packet){
//     if (DEBUG == 0){
//         return;
//     }
//     printk("Packet number: %d\n", cnt++);
//     printk("src_ip: %d\t", *src_ip);
//     printk("dst_ip: %d\t", *dst_ip);
//     printk("src_port: %d\t", *src_port);
//     printk("dst_port: %d\t", *dst_port);
//     printk("protocol: %d\t", *protocol);
//     printk("ack: %d\t", *ack);
//     printk("SYN: %d\t", is_syn_packet);
//     printk("direction: %d\n", *direction);
// }

// // This function used for debugging.
// // It will print a messege if the debug flag is 1.
// void print_message(char *messege){
//     if (DEBUG == 0){
//         return;
//     }
//     printk("%s\n", messege);
// }