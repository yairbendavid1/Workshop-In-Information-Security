#ifndef __rule_h
#define __rule_h

#include "user.h"

#define MAX_RULES 50

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	uint32_t	src_ip;
	uint32_t	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	uint8_t    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	uint32_t	dst_ip;
	uint32_t	dst_prefix_mask; 	// as above
	uint8_t    dst_prefix_size; 	// as above	
	uint16_t	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	uint16_t	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	prot_t	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	uint8_t	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

typedef enum { 
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;

// functions to convert rule_t to a string we can send to the module and vice versa.
static void create_buff_from_rule(const rule_t *rule, char *buf);
static void create_rule_from_buff(rule_t *rule, const char *buf);

// functions to copy from and to buffer and increase the buffet address to match the size writen/read.
static void copy_to_buff_and_increase(char **buf_ptr, void *var, size_t n);
static void copy_from_buff_and_increase(char **buf_ptr, void *var, size_t n);

// functions to convert a string to a rule_t and his attributes.
static int convert_string_to_rule(char *str, rule_t *rule);
static int convert_string_to_direction(char *str, direction_t *direction);
static int convert_string_to_ip_and_mask(char *str, uint32_t *ip, uint8_t *prefix_size);
static int convert_string_to_protocol(char *str, prot_t *protocol);
static int convert_string_to_port(char *str, uint16_t *port);
static int convert_string_to_ack(char *str, ack_t *ack);
static int convert_string_to_action(char *str, uint8_t *action);



static int load_rules(const char *rule_db_file_path, rule_t *rules);
#endif