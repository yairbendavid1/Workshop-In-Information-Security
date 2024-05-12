#include "UserInterface.h"
#include "UserLogManager.h"
#include "UserRuleManager.h"
#include "UserConnectionManager.h"

#define RESET_LOG_PATH "/sys/class/fw/fw_log/reset"
#define READ_LOG_PATH "/dev/fw_log"

// This function will be called when the user enter the command "reset_log"
// This function will reset the log list
int clear_log()
{
    // Open the sysfs log device
    FILE *log_sysfs_fd = fopen(RESET_LOG_PATH, "wb");
    if (log_sysfs_fd == NULL){ // on error:
        printf("Error: Cant open the log sysfs\n");
        return EXIT_FAILURE;
    }

    // Write to the sysfs log device to "trigger" the reset
    if (fwrite("r", 1, 1, log_sysfs_fd) != 1){ // on error:
            printf("Error: Cant write to log sysfs\n");
            return EXIT_FAILURE;
        }

    // Close the sysfs log device
    fclose(log_sysfs_fd);

    return EXIT_SUCCESS;
}


// This function will be called when the user enter the command "show_log"
// This function will print the log list to the user
int show_log()
{
    // Open the log device
    FILE *log_fd = fopen(READ_LOG_PATH, "rb");
    if (log_fd == NULL){ // on error:
        printf("Error: Cant open the log device\n");
        return EXIT_FAILURE;
    }

    // First we need to read the amount of the logs from the log device
    // This way we will know how much logs we need to read.
    uint32_t size;
    if (fread(&size, sizeof(uint32_t), 1, log_fd) != 1){ // on error:
        printf("Error: Cant read from the log device\n");
        return EXIT_FAILURE;
    }

    // Now we will read the log buffers from the log device and print them to the user

    // the size of the buffer:
    int buff_size = sizeof(unsigned long) + sizeof(unsigned char) + sizeof(unsigned char) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(reason_t) + sizeof(unsigned int);
    char log_row_buf[buff_size]; // The buffer we will read the logs to
    log_row_t current_log;
    char log_string[256];

    // Before we print the logs, we need to print the titles of the columns of the log table.
    printf("timestamp			src_ip			dst_ip			src_port	dst_port	protocol	action	reason			count\n");

    // Now we will read the logs from the log device and print them to the user
    for (int i = 0; i < size; i++)
    {
        // Read the log buffer from the log device
        if (fread(log_row_buf, buff_size, 1, log_fd) != 1){ // on error:
            printf("Error: Cant read from the log device\n");
            return EXIT_FAILURE;
        }

        // Convert the buffer to a log struct
        convert_buff_to_log(&current_log, log_row_buf);
        //print_log(&current_log);

        // Convert the log struct to a string
        convert_log_to_string(&current_log, log_string);

        // Print the string to the user
        printf("%s\n", log_string);
    }
    return EXIT_SUCCESS;
}



void print_log(log_row_t *log){
    printf("time: %ld\n", log->timestamp);
    printf("protocol: %d\n", log->protocol);
    printf("action: %d\n", log->action);
    printf("src_ip: %d\n", log->src_ip);
    printf("dst_ip: %d\n", log->dst_ip);
    printf("src_port: %d\n", log->src_port);
    printf("dst_port: %d\n", log->dst_port);
    printf("reason: %d\n", log->reason);
    printf("count: %d\n", log->count);
}



// This function will convert a buffer read from the log device to a log struct
// The format of the buffer is:
// timestamp, protocol, action, src_ip, dst_ip, src_port, dst_port, reason, count
void convert_buff_to_log(log_row_t *log, char *buf)
{
    copy_from_buff_and_increase(&buf, &log->timestamp, sizeof(log->timestamp));
    copy_from_buff_and_increase(&buf, &log->protocol, sizeof(log->protocol));
    copy_from_buff_and_increase(&buf, &log->action, sizeof(log->action));
    copy_from_buff_and_increase(&buf, &log->src_ip, sizeof(log->src_ip));
    copy_from_buff_and_increase(&buf, &log->dst_ip, sizeof(log->dst_ip));
    copy_from_buff_and_increase(&buf, &log->src_port, sizeof(log->src_port));
    copy_from_buff_and_increase(&buf, &log->dst_port, sizeof(log->dst_port));
    copy_from_buff_and_increase(&buf, &log->reason, sizeof(log->reason));
    copy_from_buff_and_increase(&buf, &log->count, sizeof(log->count));
}

// Thsi function will convert a log to a string
void convert_log_to_string(log_row_t *log, char *log_string)
{
    log_convert_timestamp_to_string(log->timestamp, log_string);
    log_convert_ip_to_string(log->src_ip, log_string);
    log_convert_ip_to_string(log->dst_ip, log_string);
    log_convert_port_to_string(log->src_port, log_string);
    log_convert_port_to_string(log->dst_port, log_string);
    log_convert_protocol_to_string(log->protocol, log_string);
    log_convert_action_to_string(log->action, log_string);
    log_convert_reason_to_string(log->reason, log_string);
    log_convert_count_to_string(log->count, log_string);
}


void log_convert_timestamp_to_string(unsigned long timestamp, char *log_string)
{
    time_t time = timestamp;
    struct tm *time_info = localtime(&time);
    strftime(log_string, 256, "%Y-%m-%d %H:%M:%S", time_info);
    strcat(log_string, "		");
}


void log_convert_ip_to_string(uint32_t ip, char *log_string)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    strcat(log_string, inet_ntoa(ip_addr));
    strcat(log_string, "		");
}


void log_convert_port_to_string(uint16_t port, char *log_string)
{
    char port_str[8];
    if (port == 0){
      sprintf(port_str, "any");
    }
    else{
    sprintf(port_str, "%d", port);
    }
    strcat(log_string, port_str);
    strcat(log_string, "		");
}


void log_convert_protocol_to_string(unsigned char protocol, char *log_string)
{
    char *protocol_str;
    if (protocol == PROT_ICMP)
    {
        protocol_str = "ICMP";
    }
    else if (protocol == PROT_TCP)
    {
        protocol_str = "TCP";
    }
    else if (protocol == PROT_UDP)
    {
        protocol_str = "UDP";
    }
    else{
        char protocol_str[8];
        sprintf(protocol_str, "%d", protocol);
    }
    strcat(log_string, protocol_str);
    strcat(log_string, "		");
}


void log_convert_action_to_string(unsigned char action, char *log_string)
{
    char *action_str;
    if (action == NF_ACCEPT)
    {
        action_str = "ACCEPT";
    }
    else if (action == NF_DROP)
    {
        action_str = "DROP";
    }
    strcat(log_string, action_str);
    strcat(log_string, "	");
}


void log_convert_reason_to_string(int reason, char *log_string)
{
    if (reason == REASON_FW_INACTIVE)
    {
        char *reason_str;
        reason_str = "FW_INACTIVE";
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }
    if (reason == REASON_NO_MATCHING_RULE)
    {
        char *reason_str;
        reason_str = "NO_MATCHING_RULE";
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }
    if (reason == REASON_XMAS_PACKET)
    {
        char *reason_str;
        reason_str = "XMAS_PACKET";
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }
    if (reason == REASON_NO_MATCHING_CONNECTION)
    {
        char *reason_str;
        reason_str = "No Connection Found"; 
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }
    if (reason == REASON_INVALID_CONNECTION_STATE)
    {
        char *reason_str;
        reason_str = "Protocol Violation";
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }
    if (reason == REASON_VALID_CONNECTION_EXIST)
    {
        char *reason_str;
        reason_str = "Connection Exist";
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }
    if (reason == REASON_PROXY)
    {
        char *reason_str;
        reason_str = "Proxy";
        strcat(log_string, reason_str);
        strcat(log_string, "		");
        return;
    }

    char reason_str[8];
    sprintf(reason_str, "%d", reason);
    strcat(log_string, reason_str);
    strcat(log_string, "		");
}


void log_convert_count_to_string(unsigned int count, char *log_string)
{
    char count_str[8];
    sprintf(count_str, "%d", count);
    strcat(log_string, count_str);
}
