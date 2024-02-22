#include "UserInterface.h"
#include "UserConnectionManager.h" 
#include "UserLogManager.h"
#include "UserRuleManager.h"

#define CONN_PATH "/sys/class/fw/conns/conns"


int show_conns(){
    // Open the connections device
    FILE *con_fd = fopen(CONN_PATH, "rb");
    if (con_fd == NULL){ // on error:
        printf("Error: Cant open the con device\n");
        return EXIT_FAILURE;
    }

    // First we need to read the amount of the connections from the connections device
    // This way we will know how much connections we need to read.
    uint32_t size;
    if (fread(&size, sizeof(uint32_t), 1, con_fd) != 1){ // on error:
        printf("Error: Cant read from the connection device\n");
        return EXIT_FAILURE;
    }

    // Now we will read the conn buffers from the connection device and print them to the user

    // the size of the buffer:
    int buff_size = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(direction_t) + sizeof(tcp_status_t);
    char con_row_buf[buff_size]; // The buffer we will read the logs to
    connection_t current_con;
    char con_string[256];

    // Before we print the logs, we need to print the titles of the columns of the log table.
    printf("in_entity_ip			in_entity_port			out_entity_ip	out_entity_port 	next_directrion 	status\n");

    // Now we will read the logs from the log device and print them to the user
    for (int i = 0; i < size; i++)
    {
        // Read the log buffer from the log device
        if (fread(con_row_buf, buff_size, 1, con_fd) != 1){ // on error:
            printf("Error: Cant read from the log device\n");
            return EXIT_FAILURE;
        }

        // Convert the buffer to a log struct
        convert_buff_to_con(&current_con, con_row_buf);
        //print_log(&current_log);

        // Convert the log struct to a string
        convert_con_to_string(&current_con, con_string);

        // Print the string to the user
        printf("%s\n", con_string);
    }
    return EXIT_SUCCESS;
}

// This function will convert a buffer to a connection struct
void convert_buff_to_con(connection_t *con, char *buf){
    printf("converting buffer to connection\n");
    copy_from_buff_and_increase(&buf, &con->int_ip, sizeof(con->int_ip));
    printf("int ip: %d\n", con->int_ip);
    copy_from_buff_and_increase(&buf, &con->int_port, sizeof(con->int_port));
    printf("int port: %d\n", con->int_port);
    copy_from_buff_and_increase(&buf, &con->out_ip, sizeof(con->out_ip));
    printf("out ip: %d\n", con->out_ip);
    copy_from_buff_and_increase(&buf, &con->out_port, sizeof(con->out_port));
    printf("out port: %d\n", con->out_port);
    copy_from_buff_and_increase(&buf, &con->status, sizeof(con->status));
    printf("status: %d\n", con->status);
    copy_from_buff_and_increase(&buf, &con->direction, sizeof(con->direction));
    printf("direction: %d\n", con->direction);
}

// This function will convert a connection struct to a string
void convert_con_to_string(connection_t *con, char *con_string){
    printf("converting connection to string\n");
    con_convert_ip_to_string(con->int_ip, con_string);
    printf("int ip: %d\n", con->int_ip);
    con_convert_port_to_string(con->int_port, con_string);
    printf("int port: %d\n", con->int_port);
    con_convert_ip_to_string(con->out_ip, con_string);
    printf("out ip: %d\n", con->out_ip);
    con_convert_port_to_string(con->out_port, con_string);
    printf("out port: %d\n", con->out_port);
    con_convert_direction_to_string(con->direction, con_string);
    printf("direction: %d\n", con->direction);
    con_convert_status_to_string(con->status, con_string);
    printf("status: %d\n", con->status);
}


void con_convert_ip_to_string(uint32_t ip, char *con_string)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    strcat(con_string, inet_ntoa(ip_addr));
    strcat(con_string, "		");
}

void con_convert_port_to_string(uint16_t port, char *con_string)
{
    char port_str[8];
    if (port == 0){
      sprintf(port_str, "any");
    }
    else{
    sprintf(port_str, "%d", port);
    }
    strcat(con_string, port_str);
    strcat(con_string, "		");
}


void con_convert_direction_to_string(direction_t direction, char *con_string)
{
    char direction_str[8];
    if (direction == DIRECTION_ANY){
      sprintf(direction_str, "any");
    }
    else if (direction == DIRECTION_IN){
      sprintf(direction_str, "in");
    }
    else{
      sprintf(direction_str, "out");
    }
    strcat(con_string, "		");
}


void con_convert_status_to_string(tcp_status_t status, char *con_string)
{
    char status_str[20];
    if (status == PRESYN){
      sprintf(status_str, "presyn");
    }
    if (status ==  SYN_ACK){
      sprintf(status_str, "synack");
    }
    if (status ==  SYN){
      sprintf(status_str, "syn");
    }
    if (status ==  ESTABLISHED){
      sprintf(status_str, "established");
    }
    if (status == A_SENT_FIN){
      sprintf(status_str, "a_sent_fin");
    }
    if (status == A_FIN_B_ACK){
      sprintf(status_str, "a_fin_b_ack");
    }
    if (status == A_FIN_B_FIN){
      sprintf(status_str, "a_fin_b_fin");
    }
    if (status == A_FIN_B_FIN_ACK){
      sprintf(status_str, "a_fin_b_fin_ack");
    }
    if (status == A_FIN2){
      sprintf(status_str, "a_fin2");
    }
    if (status == B_FIN2){
      sprintf(status_str, "b_fin2");
    }
    if (status == B_ACK){
      sprintf(status_str, "b_ack");
    }
    strcat(con_string, status_str);
}