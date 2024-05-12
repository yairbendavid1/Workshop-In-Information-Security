#ifndef __CONN_HANDLER_H__
#define __CONN_HANDLER_H__

int show_conns();
void convert_buff_to_con(connection_t *con, char *buf);
void convert_con_to_string(connection_t *con, char *con_string);
void con_convert_port_to_string(uint16_t port, char *con_string);
void con_convert_ip_to_string(uint32_t ip, char *con_string);
void con_convert_direction_to_string(direction_t direction, char *con_string);
void con_convert_status_to_string(tcp_status_t status, char *con_string);

#endif // __CONN_HANDLER_H__