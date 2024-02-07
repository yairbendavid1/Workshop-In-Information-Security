#ifndef _LOG_H_
#define _LOG_H_


#include "user.h"
#include "rule.h"


int clear_log(void);
int show_log(void);
void convert_buff_to_log(log_row_t *log, char *buff);
void convert_log_to_string(log_row_t *log, char *buff);

// functions to convert log to string
void log_convert_timestamp_to_string(unsigned long timestamp, char *log_string);
void log_convert_ip_to_string(uint32_t ip, char *log_string);
void log_convert_port_to_string(uint16_t port, char *log_string);
void log_convert_protocol_to_string(unsigned char protocol, char *log_string);
void log_convert_action_to_string(unsigned char action, char *log_string);
void log_convert_reason_to_string(reason_t reason, char *log_string);
void log_convert_count_to_string(unsigned int count, char *log_string);


#endif 
