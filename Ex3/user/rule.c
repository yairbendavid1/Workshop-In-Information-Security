#include "user.h"
#include "log.h"
#include "rule.h"


void copy_to_buff_and_increase(char **buf_ptr, const void *var, size_t n){
    memcpy(*buf_ptr, var, n);
    *buf_ptr += n;
}

void copy_from_buff_and_increase(char **buf_ptr, const void *var, size_t n){
    memcpy(var, *buf_ptr, n);
    *buf_ptr += n;
}

// This function converts a rule struct to a buffer that can be sent to the kernel module.
// The format of the buffer is:
// <rule_name> <direction> <src_ip> <src_prefix_mask> <src_prefix_size> <dst_ip> <dst_prefix_mask> <dst_prefix_size> <src_port> <dst_port> <protocol> <ack> <action>
void create_buff_from_rule(const rule_t *rule, char *buf){
    copy_to_buff_and_increase(&buf, rule->rule_name, 20); // rule name
    copy_to_buff_and_increase(&buf, &rule->direction, sizeof(rule->direction)); // direction
    copy_to_buff_and_increase(&buf, &rule->src_ip, sizeof(rule->src_ip)); // src ip
    copy_to_buff_and_increase(&buf, &rule->src_prefix_mask, sizeof(rule->src_prefix_mask)); // src prefix mask
    copy_to_buff_and_increase(&buf, &rule->src_prefix_size, sizeof(rule->src_prefix_size)); // src prefix size
    copy_to_buff_and_increase(&buf, &rule->dst_ip, sizeof(rule->dst_ip)); // dst ip
    copy_to_buff_and_increase(&buf, &rule->dst_prefix_mask, sizeof(rule->dst_prefix_mask)); // dst prefix mask
    copy_to_buff_and_increase(&buf, &rule->dst_prefix_size, sizeof(rule->dst_prefix_size)); // dst prefix size
    copy_to_buff_and_increase(&buf, &rule->src_port, sizeof(rule->src_port)); // src port
    copy_to_buff_and_increase(&buf, &rule->dst_port, sizeof(rule->dst_port)); // dst port
    copy_to_buff_and_increase(&buf, &rule->protocol, sizeof(rule->protocol)); // protocol
    copy_to_buff_and_increase(&buf, &rule->ack, sizeof(rule->ack)); // ack
    copy_to_buff_and_increase(&buf, &rule->action, sizeof(rule->action)); // action
    }





// This function converts a buffer that was sent from the kernel module to a rule struct.
// The format of the buffer is:
// <rule_name> <direction> <src_ip> <src_prefix_mask> <src_prefix_size> <dst_ip> <dst_prefix_mask> <dst_prefix_size> <src_port> <dst_port> <protocol> <ack> <action>
void create_rule_from_buff(const rule_t *rule, char *buf){
    copy_from_buff_and_increase(&buf, rule->rule_name, 20); // rule name
    copy_from_buff_and_increase(&buf, &rule->direction, sizeof(rule->direction)); // direction
    copy_from_buff_and_increase(&buf, &rule->src_ip, sizeof(rule->src_ip)); // src ip
    copy_from_buff_and_increase(&buf, &rule->src_prefix_mask, sizeof(rule->src_prefix_mask)); // src prefix mask
    copy_from_buff_and_increase(&buf, &rule->src_prefix_size, sizeof(rule->src_prefix_size)); // src prefix size
    copy_from_buff_and_increase(&buf, &rule->dst_ip, sizeof(rule->dst_ip)); // dst ip
    copy_from_buff_and_increase(&buf, &rule->dst_prefix_mask, sizeof(rule->dst_prefix_mask)); // dst prefix mask
    copy_from_buff_and_increase(&buf, &rule->dst_prefix_size, sizeof(rule->dst_prefix_size)); // dst prefix size
    copy_from_buff_and_increase(&buf, &rule->src_port, sizeof(rule->src_port)); // src port
    copy_from_buff_and_increase(&buf, &rule->dst_port, sizeof(rule->dst_port)); // dst port
    copy_from_buff_and_increase(&buf, &rule->protocol, sizeof(rule->protocol)); // protocol
    copy_from_buff_and_increase(&buf, &rule->ack, sizeof(rule->ack)); // ack
    copy_from_buff_and_increase(&buf, &rule->action, sizeof(rule->action)); // action
    }


// This function converts a string (readen from a file) to a rule struct.
// The string is in the following format:
// <rule_name> <direction> <src_ip> <dst_ip>  <protocol> <src_port> <dst_port> <ack> <action>
// returns 1 if succeed, 0 if failed.
int convert_string_to_rule(char *str, rule_t *rule){
    // Since we know the length of each field and the format of the string, we can use sscanf to read the string.
    // First, we need to allocate some strings to save the fields in - note that the strings will not be apply-ready to the rule struct.
    // specificly, name is just a string so we can copy it to the rule struct.
    char direction[4]; // "in" or "out" or "any"
    char src_ip[40]; // xxx.xxx.xxx.xxx/mask
    char dst_ip[40]; // xxx.xxx.xxx.xxx/mask
    char src_port[6]; // 0-65535 or "any" or ">1023"
    char dst_port[6]; // 0-65535 or "any" or ">1023"
    char protocol[4]; // "icmp" or "tcp" or "udp" or "any"
    char ack[4]; // "no" or "yes" or "any"
    char action[7]; // "accept" or "drop"
    // We want to secure that every function is succeed, so we will use a flag to indicate if a function failed.
    int direction_flag = 0, src_ip_flag = 0, dst_ip_flag = 0, src_port_flag = 0, dst_port_flag = 0, protocol_flag = 0, ack_flag = 0, action_flag = 0;
    // Now we can read the string.
    if (sscanf(str, "%s %s %s %s %s %s %s %s %s", rule->rule_name, direction, src_ip, dst_ip, protocol, src_port, dst_port, ack, action) != 9){
        printf("Error reading the string\n");
        return 0;
    }

    // Now we need to convert the strings to the correct types and save them in the rule struct.
    direction_flag = convert_string_to_direction(direction, &rule->direction);
    src_ip_flag = convert_string_to_ip_and_mask(src_ip, &rule->src_ip, &rule->src_prefix_mask, &rule->src_prefix_size);
    dst_ip_flag = convert_string_to_ip_and_mask(dst_ip, &rule->dst_ip, &rule->dst_prefix_mask, &rule->dst_prefix_size);
    protocol_flag = convert_string_to_protocol(protocol, &rule->protocol);
    src_port_flag = convert_string_to_port(src_port, &rule->src_port);
    dst_port_flag = convert_string_to_port(dst_port, &rule->dst_port);
    ack_flag = convert_string_to_ack(ack, &rule->ack);
    action_flag = convert_string_to_action(action, &rule->action);

    // Now we need to check if all the functions succeed.
    if (direction_flag == 0 || src_ip_flag == 0 || dst_ip_flag == 0 || src_port_flag == 0 || dst_port_flag == 0 || protocol_flag == 0 || ack_flag == 0 || action_flag == 0){
        printf("Error converting string to rule\n");
        return 0;
    }
    return 1;
}


// This function converts a rule struct to a string we can print to the user.
// The string is in the following format:
// <rule_name> <direction> <src_ip>/<src_mask_size> <dst_ip>/<dst_mask_size> <protocol> <src_port> <dst_port> <ack> <action>
int convert_rule_to_string(rule_t *rule, char *str){
    // first we will save some flags to indicate if a function failed.
    int direction_flag = 0, src_ip_flag = 0, dst_ip_flag = 0, src_port_flag = 0, dst_port_flag = 0, protocol_flag = 0, ack_flag = 0, action_flag = 0;
    // Now we can convert the rule struct to a string.
    strcpy(str, rule->rule_name); // rule name
    strcat(str, " "); // add space
    direction_flag = convert_direction_to_string(rule->direction, str + strlen(str)); // direction
    strcat(str, " "); // add space
    src_ip_flag = convert_ip_and_mask_to_string(rule->src_ip, rule->src_prefix_size, str + strlen(str)); // src ip + mask
    strcat(str, " "); // add space
    dst_ip_flag = convert_ip_and_mask_to_string(rule->dst_ip, rule->dst_prefix_size, str + strlen(str)); // dst ip + mask
    strcat(str, " "); // add space
    protocol_flag = convert_protocol_to_string(rule->protocol, str + strlen(str)); // protocol
    strcat(str, " "); // add space
    src_port_flag = convert_port_to_string(rule->src_port, str + strlen(str)); // src port
    strcat(str, " "); // add space
    dst_port_flag = convert_port_to_string(rule->dst_port, str + strlen(str)); // dst port
    strcat(str, " "); // add space
    ack_flag = convert_ack_to_string(rule->ack, str + strlen(str)); // ack
    strcat(str, " "); // add space
    action_flag = convert_action_to_string(rule->action, str + strlen(str)); // action
    strcat(str, "\n"); // add new line
    // Now we need to check if all the functions succeed.
    if (direction_flag == 0 || src_ip_flag == 0 || dst_ip_flag == 0 || src_port_flag == 0 || dst_port_flag == 0 || protocol_flag == 0 || ack_flag == 0 || action_flag == 0){
        printf("Error converting rule to string\n");
        return 0;
    }
    // if all the functions succeed, we can return 1.
    return 1;

}


// This function converts a direction string to a direction_t enum.
// returns 1 if succeed, 0 if failed.
int convert_string_to_direction(char *str, direction_t *direction){
    if (strcmp(str, "in") == 0){
        *direction = DIRECTION_IN;
        return 1;
    }
    else if (strcmp(str, "out") == 0){
        *direction = DIRECTION_OUT;
        return 1;
    }
    else if (strcmp(str, "any") == 0){
        *direction = DIRECTION_ANY;
        return 1;
    }
    else{
        printf("Error in direction\n");
        return 0;
    }
}


// This function converts a direction_t enum to a direction string.
// returns 1 if succeed, 0 if failed.
int convert_direction_to_string(direction_t direction, char *str){
    if (direction == DIRECTION_IN){
        strcat(str, "in");
        return 1;
    }
    else if (direction == DIRECTION_OUT){
        strcat(str, "out");
        return 1;
    }
    else if (direction == DIRECTION_ANY){
        strcat(str, "any");
        return 1;
    }
    else{
        printf("Error in direction\n");
        return 0;
    }
}


// This function converts an IP and a mask (network byte order) to IP/mask string.
// IP string format: xxx.xxx.xxx.xxx/mask_size
// returns 1 if succeed, 0 if failed.
int convert_ip_and_mask_to_string(uint32_t ip, uint8_t mask_size, char *str){
    // First we need to check if the IP is "any".
    if (ip == 0){
        strcat(str, "any");
        return 1;
    }

    // we need to convert the IP (network byte order) to IP string.
    // we can use inet_ntoa() to convert the IP (network byte order) to IP string.
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    char *ip_str = inet_ntoa(ip_addr);
    if (ip_str == NULL){
        printf("Error converting IP to IP string\n");
        return 0;
    }
    strcat(str, ip_str);
    // Now we need to add the "/<mask_size>" to str.
    char mask_size_str[4]; // 0-32
    sprintf(mask_size_str, "/%u", mask_size);
    strcat(str, mask_size_str);
    return 1;
}


// This function converts an IP and a mask string to IP (network byte order) and mask (network byte order) and prefix size.
// IP string format: xxx.xxx.xxx.xxx
// str_prefix: a string that contains the prefix size (0-32)
// returns 1 if succeed, 0 if failed.
int convert_string_to_ip_and_mask(char* str, uint32_t *ip, uint32_t *mask, uint8_t *prefix_size){
    // First we need to check if the string is "any" or IP/mask.
    if (strcmp(str, "any") == 0){
        *ip = 0;
        *mask = 0;
        *prefix_size = 0;
        return 1;
    }
    // If the string is not "any", we need to extract the IP and the mask.
    // We know the format of the string, so we can use sscanf to read the string.
    char str_ip[20]; // xxx.xxx.xxx.xxx
    int seg1, seg2, seg3, seg4, prefix; // 0-32
    sscanf(str, "%u.%u.%u.%u/%u", &seg1, &seg2, &seg3 , &seg4, &prefix);
    sprintf(str_ip, "%u.%u.%u.%u", seg1, seg2, seg3, seg4);
    // Now we need to convert the IP string to IP (network byte order).
    // we can use inet_aton() to convert the IP string to IP (network byte order).
    struct in_addr ip_struct;
    if (inet_aton(str_ip, ip_struct) == 0){
        printf("Error converting IP string %s to IP\n", str_ip);
        return 0;
    }
    *ip = ip_struct.s_addr;
    *prefix_size = (uint8_t)prefix;
    // ..and then we can create the mask from the prefix size.
    *mask = ((uint32_t)(-1)) << (32 - prefix); // host byte order mask
    return 1;

}


// This function converts a protocol to a string.
// returns 1 if succeed, 0 if failed.
int convert_protocol_to_string(prot_t protocol, char *str){
    if (protocol == PROT_ICMP){
        strcat(str, "icmp");
        return 1;
    }
    else if (protocol == PROT_TCP){
        strcat(str, "tcp");
        return 1;
    }
    else if (protocol == PROT_UDP){
        strcat(str, "udp");
        return 1;
    }
    else if (protocol == PROT_ANY){
        strcat(str, "any");
        return 1;
    }
    else{
        printf("Error in protocol\n");
        return 0;
    }
}


// This function converts a protocol string to a prot_t enum.
int convert_string_to_protocol(char *str, prot_t *protocol){
    if (strcmp(str, "any") == 0){
        *protocol = PROT_ANY;
        return 1;
    }
    if (strcmp(str, "ICMP") == 0){
        *protocol = PROT_ICMP;
        return 1;
    }
    if (strcmp(str, "TCP") == 0){
        *protocol = PROT_TCP;
        return 1;
    }
    if (strcmp(str, "UDP") == 0){
        *protocol = PROT_UDP;
        return 1;
    }
    else{
        printf("Error converting protocol string to protocol number: not a valid protocol\n");
        return 0;
    }
}


// This function converts a port string to a port number.
// returns 1 if succeed, 0 if failed.
int convert_string_to_port(char *str, uint16_t *port){

    if (strcmp(str, "any") == 0){
        *port = (uint16_t)0;
        return 1;
    }
    if (strcmp(str, ">1023") == 0){
      *port = (uint16_t)1024;
      return 1;
    }
    else {
      int p = atoi(str);
      if (p > 1023){
        printf("Error on port: port is too big\n");
        return 0;
      }
      *port = (uint16_t)p;
      return 1;
    }
}


// This function converts port to a string.
// returns 1 if succeed, 0 if failed.
int convert_port_to_string(uint16_t port, char *str){
    if (port == 0){
        strcat(str, "any");
        return 1;
    }
    else if (port == 1024){
        strcat(str, ">1023");
        return 1;
    }
    else{
        char port_str[6];
        sprintf(port_str, "%u", port);
        strcat(str, port_str);
        return 1;
    }
}


// This function converts an ack_t enum to an ack string.
// returns 1 if succeed, 0 if failed.
int convert_string_to_ack(char *str, ack_t *ack){
    if (strcmp(str, "no") == 0){
        *ack = ACK_NO;
        return 1;
    }
    else if (strcmp(str, "yes") == 0){
        *ack = ACK_YES;
        return 1;
    }
    else if (strcmp(str, "any") == 0){
        *ack = ACK_ANY;
        return 1;
    }
    else{
        printf("Error converting ack string to ack number: not a valid ack\n");
        return 0;
    }
}


// This function converts an ack to an ack string.
// returns 1 if succeed, 0 if failed.
int convert_ack_to_string(ack_t ack, char *str){
    if (ack == ACK_NO){
        strcat(str, "no");
        return 1;
    }
    else if (ack == ACK_YES){
        strcat(str, "yes");
        return 1;
    }
    else if (ack == ACK_ANY){
        strcat(str, "any");
        return 1;
    }
    else{
        printf("Error converting ack number to ack string: not a valid ack\n");
        return 0;
    }
}


// This function converts an action string to an action.
int convert_string_to_action(char *str, uint8_t *action){
    if (strcmp(str, "accept") == 0){
        *action = 1; // NF_ACCEPT - can't use NF_ACCEPT because it's not defined in user.h
        return 1;
    }
    else if (strcmp(str, "drop") == 0){
        *action = 0; // NF_DROP - can't use NF_DROP for the same reasons as NF_ACCEPT
        return 1;
    }
    else{
        printf("Error converting action string to action number: not a valid action\n");
        return 0;
    }
}


// This function converts an action to an action string.
int convert_action_to_string(uint8_t action, char *str){
    if (action == 1){
        strcat(str, "accept");
        return 1;
    }
    else if (action == 0){
        strcat(str, "drop");
        return 1;
    }
    else{
        printf("Error converting action number to action string: not a valid action\n");
        return 0;
    }
}


int load_rules(const char *rule_db_file_path){
    rule_t rules[MAX_RULES];
    FILE *rules_table_fp;
    FILE *sys_fs_fp;
    char line[256];
    int size_of_kernel_buff = 20 + sizeof(direction_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(prot_t) + sizeof(ack_t) + sizeof(uint8_t);
    char buf_for_kernel[size_of_kernel_buff];
    uint8_t lines_read = 0;
    rules_table_fp = fopen(rule_db_file_path, "r");
    if (rules_table_fp == NULL){
        printf("Error opening file!\n");
        return -1;
    }
    // Read the file line by line and convert each line to a rule struct and save it in the rules array.
    while (fgets(line, sizeof(line), rules_table_fp) != NULL){
        printf("read the #%i line: %s\n", lines_read, line);
        if (convert_string_to_rule(line, rules + lines_read) == -1){
            printf("Error converting string to rule\n");
            return -1;
        }
        lines_read++;
        }

    // Now we need to send them to the kernel module.
    // In order to save kernel resources, we will send each rule as a buffer containing only the rule struct.
    // The format of the buffer is:
    // <rule_name> <direction> <src_ip> <dst_ip>  <protocol> <src_port> <dst_port> <ack> <action>

    // First, we need to open the rules device.
    sys_fs_fp = fopen(RULE_SYSFS_PATH, "wb");
    if (sys_fs_fp == NULL){ // check if the file was opened successfully
        printf("Error opening rules device\n");
        return -1;
    }


    // Now we can send the rules to the kernel module.
    // first, we need to send the amount of rules so the kernel module will know how many rules to expect.
    // then we will send each rule as a buffer containing only the rule info.

    if (fwrite(&lines_read, 1, 1, sys_fs_fp) != 1){ // write the amount of rules to the rules device
        printf("Error writing to rules device\n");
        return -1;
    }

    for (uint8_t i = 0; i < lines_read; i++){ // iterate over the rules array
        // Convert the rule struct to a buffer.
        create_buff_from_rule(rules + i, buf_for_kernel);
        // Write the buffer to the rules device.
        if (fwrite(buf_for_kernel, size_of_kernel_buff, 1, sys_fs_fp) != 1){
            printf("Error writing to rules device\n");
            return -1;
        }
    }

    fclose(rules_table_fp);
    fclose(sys_fs_fp);
    return 0;
}

// This function reads the rules from the kernel module.

int show_rules(){
    rule_t rules[MAX_RULES];
    FILE *sys_fs_fp;
    int size_of_kernel_buff = 20 + sizeof(direction_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(prot_t) + sizeof(ack_t) + sizeof(uint8_t);
    char buf_from_kernel[size_of_kernel_buff];
    uint8_t amount_of_rules;

    // First, we need to open the rules device.
    sys_fs_fp = fopen(RULE_SYSFS_PATH, "rb");

    if (sys_fs_fp == NULL){ // check if the file was opened successfully
        printf("Error opening rules device\n");
        return -1;
    }


    // Now we can read the rules from the kernel module.
    // first, we need to read the amount of rules so we know how many rules to expect.
    // then we will read each rule as a buffer containing only the rule info.

    if (fread(&amount_of_rules, 1, 1, sys_fs_fp) != 1){ // write the amount of rules to the rules device
        printf("Error reading to rules device\n");
        return -1;
    }

    for (uint8_t i = 0; i < amount_of_rules; i++){
        // Read the buffer from the rules device.
        if (fread(buf_from_kernel, size_of_kernel_buff, 1, sys_fs_fp) != 1){
            printf("Error reading from rules device\n");
            return -1;
        }
        // Convert the buffer to a rule struct.
        create_rule_from_buff(rules + i, buf_from_kernel);
    }

    // Now after we save all the rules in the rules array, we can print them.
    for (uint8_t l = 0; l < amount_of_rules; l++){
        convert_rule_to_string(rules + l, buf_from_kernel);
        printf("%s", buf_from_kernel);
    }

    fclose(sys_fs_fp);
    return 0;
}


void print_rule(rule_t rule){
    rule_t *rule_ptr = &rule;
    printf("rule name: %s\n", rule_ptr->rule_name);
    printf("direction: %d\n", rule_ptr->direction);
    printf("src ip: %u\n", rule_ptr->src_ip);
    printf("src prefix mask: %u\n", rule_ptr->src_prefix_mask);
    printf("src prefix size: %u\n", rule_ptr->src_prefix_size);
    printf("dst ip: %u\n", rule_ptr->dst_ip);
    printf("dst prefix mask: %u\n", rule_ptr->dst_prefix_mask);
    printf("dst prefix size: %u\n", rule_ptr->dst_prefix_size);
    printf("src port: %u\n", rule_ptr->src_port);
    printf("dst port: %u\n", rule_ptr->dst_port);
    printf("protocol: %u\n", rule_ptr->protocol);
    printf("ack: %u\n", rule_ptr->ack);
    printf("action: %u\n", rule_ptr->action);
    printf("\n");

}
