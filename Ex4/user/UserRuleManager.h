#ifndef __rule_h
#define __rule_h


#include "UserInterface.h"
#include "UserLogManager.h"


#define RULE_SYSFS_PATH "/sys/class/fw/rules/rules"



// functions to convert rule_t to a string we can send to the module and vice versa.
void create_buff_from_rule(const rule_t *rule, char *buf);
void create_rule_from_buff(const rule_t *rule, char *buf);

// functions to copy from and to buffer and increase the buffet address to match the size writen/read.
void copy_to_buff_and_increase(char **buf_ptr, const void *var, size_t n);
void copy_from_buff_and_increase(char **buf_ptr, const void *var, size_t n);

// functions to convert a string to a rule_t and his attributes.
int convert_string_to_rule(char *str, rule_t *rule);
int convert_string_to_direction(char *str, direction_t *direction);
int convert_string_to_ip_and_mask(char *str, uint32_t *ip, uint32_t *mask, uint8_t *prefix_size);
int convert_string_to_protocol(char *str, prot_t *protocol);
int convert_string_to_port(char *str, uint16_t *port);
int convert_string_to_ack(char *str, ack_t *ack);
int convert_string_to_action(char *str, uint8_t *action);

// functions to convert a rule_t and his attributes to a string.
int convert_rule_to_string(rule_t *rule, char *str);
int convert_direction_to_string(direction_t direction, char *str);
int convert_ip_and_mask_to_string(uint32_t ip, uint8_t prefix_size, char *str);
int convert_protocol_to_string(prot_t protocol, char *str);
int convert_port_to_string(uint16_t port, char *str);
int convert_ack_to_string(ack_t ack, char *str);
int convert_action_to_string(uint8_t action, char *str);

int check_rule_format(rule_t *rule);
void print_rule(rule_t rule);
int show_rules();
int load_rules(const char *rule_db_file_path);
#endif

