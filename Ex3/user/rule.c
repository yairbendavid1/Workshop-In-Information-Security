#include "rule.h"


void copy_to_buff_and_increase(char **buf_ptr, const void *var, size_t n){
    memcpy(*buf_ptr, var, n);
    *buf_ptr += n;
}


// This function converts a rule struct to a buffer that can be sent to the kernel module.
static void create_buff_from_rule(const rule_t *rule, char *buf){
    copy_to_buff_and_increase(&buf, rule->rule_name, 20);
    copy_to_buff_and_increase(&buf, &rule->direction, sizeof(rule->direction));
    copy_to_buff_and_increase(&buf, &rule->src_ip, sizeof(rule->src_ip));
    copy_to_buff_and_increase(&buf, &rule->src_prefix_size, sizeof(rule->src_prefix_size));
    copy_to_buff_and_increase(&buf, &rule->dst_ip, sizeof(rule->dst_ip));
    copy_to_buff_and_increase(&buf, &rule->dst_prefix_size, sizeof(rule->dst_prefix_size));
    copy_to_buff_and_increase(&buf, &rule->src_port, sizeof(rule->src_port));
    copy_to_buff_and_increase(&buf, &rule->dst_port, sizeof(rule->dst_port));
    copy_to_buff_and_increase(&buf, &rule->protocol, sizeof(rule->protocol));
    copy_to_buff_and_increase(&buf, &rule->ack, sizeof(rule->ack));
    copy_to_buff_and_increase(&buf, &rule->action, sizeof(rule->action));
    }


static void copy_from_buff_and_increase(const char **buf_ptr, void *var, size_t n){
    memcpy(var, *buf_ptr, n);
    *buf_ptr += n;
}


// This function converts a buffer that was sent from the kernel module to a rule struct.
static void create_rule_from_buff(char *buf, const rule_t *rule){
    copy_from_buff_and_increase(&buf, rule->rule_name, 20);
    copy_from_buff_and_increase(&buf, &rule->direction, sizeof(rule->direction));
    copy_from_buff_and_increase(&buf, &rule->src_ip, sizeof(rule->src_ip));
    copy_from_buff_and_increase(&buf, &rule->src_prefix_size, sizeof(rule->src_prefix_size));
    copy_from_buff_and_increase(&buf, &rule->dst_ip, sizeof(rule->dst_ip));
    copy_from_buff_and_increase(&buf, &rule->dst_prefix_size, sizeof(rule->dst_prefix_size));
    copy_from_buff_and_increase(&buf, &rule->src_port, sizeof(rule->src_port));
    copy_from_buff_and_increase(&buf, &rule->dst_port, sizeof(rule->dst_port));
    copy_from_buff_and_increase(&buf, &rule->protocol, sizeof(rule->protocol));
    copy_from_buff_and_increase(&buf, &rule->ack, sizeof(rule->ack));
    copy_from_buff_and_increase(&buf, &rule->action, sizeof(rule->action));
    }


// This function converts a string (readen from a file) to a rule struct.
// The string is in the following format:
// <rule_name> <direction> <src_ip> <dst_ip> <src_port> <dst_port> <protocol> <ack> <action>
// returns 1 if succeed, 0 if failed.
static int convert_string_to_rule(char *str, rule_t *rule){
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
    if (sscanf(str, "%s %s %s %s %s %s %s %s %s", rule->rule_name, direction, src_ip, dst_ip, src_port, dst_port, protocol, ack, action) != 9){
        printf("Error reading the string\n");
        return 0;
    }

    // Now we need to convert the strings to the correct types and save them in the rule struct.
    direction_flag = convert_string_to_direction(direction, &rule->direction);
    src_ip_flag = convert_string_to_ip_and_mask(src_ip, &rule->src_ip, &rule->src_prefix_mask, &rule->src_prefix_size);
    dst_ip_flag = convert_string_to_ip_and_mask(dst_ip, &rule->dst_ip, &rule->dst_prefix_mask, &rule->dst_prefix_size);
    src_port_flag = convert_string_to_port(src_port, &rule->src_port);
    dst_port_flag = convert_string_to_port(dst_port, &rule->dst_port);
    protocol_flag = convert_string_to_protocol(protocol, &rule->protocol);
    ack_flag = convert_string_to_ack(ack, &rule->ack);
    action_flag = convert_string_to_action(action, &rule->action);

    // Now we need to check if all the functions succeed.
    if (direction_flag == 0 || src_ip_flag == 0 || dst_ip_flag == 0 || src_port_flag == 0 || dst_port_flag == 0 || protocol_flag == 0 || ack_flag == 0 || action_flag == 0){
        printf("Error converting string to rule\n");
        return 0;
    }
    return 1;
}


// This function converts a direction string to a direction_t enum.
// returns 1 if succeed, 0 if failed.
static int convert_string_to_direction(char *str, direction_t *direction){
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
        return 0;
    }
}


// This function converts an IP and a mask string to IP (network byte order) and mask (network byte order) and prefix size.
// IP string format: xxx.xxx.xxx.xxx
// str_prefix: a string that contains the prefix size (0-32)
// returns 1 if succeed, 0 if failed.
static int convert_string_to_ip_and_mask(char *str, uint32_t *ip, uint32_t *mask, uint8_t *prefix_size){
    // First we need to check if the string is "any" or IP/mask.
    if (strcmp(str, "any") == 0){
        *ip = 0;
        *mask = 0;
        *prefix_size = 0;
        return 1;
    }
    // If the string is not "any", we need to extract the IP and the mask.
    // We know the format of the string, so we can use sscanf to read the string.
    char ip_str[16]; // xxx.xxx.xxx.xxx
    char str_prefix[3]; // 0-32
    sscanf(str, "%s/%s", ip_str, str_prefix);

    // Now we need to convert the IP string to IP (network byte order).
    // we can use inet_aton() to convert the IP string to IP (network byte order)..
    if (inet_aton(ip_str, ip) == 0){
        printf("Error converting IP string to IP\n");
        return 0;
    }
    uint8_t size = atoi(str_prefix);
    *prefix_size = size;
    // ..and then we can create the mask from the prefix size.
    *mask = (uint32_t)(pow(2, size) - 1) << (32 - size); // host byte order mask
    return 1;

}


// This function converts a port string to a port number.
// returns 1 if succeed, 0 if failed.
static int convert_string_to_port(char *str, uint16_t *port){
    if (strcmp(str, "any") == 0){
        *port = (uint16_t)0;
        return 1;
    }
    else if (strcmp(str, ">1023") == 0){
        *port = (uint16_t)1024;
        return 1;
    }
    else{
        uint16_t p = atoi(str);
        if (p > 0 && p <= 1023){
            *port = p;
            return 1;
        }
        else{
            printf("Error converting port string to port number: not a valid port\n");
            return 0;
        }
    }
}


// This function converts a protocol string to a prot_t enum.
static int convert_string_to_protocol(char *str, prot_t *protocol){
    if (strcmp(str, "icmp") == 0){
        *protocol = PROT_ICMP;
        return 1;
    }
    else if (strcmp(str, "tcp") == 0){
        *protocol = PROT_TCP;
        return 1;
    }
    else if (strcmp(str, "udp") == 0){
        *protocol = PROT_UDP;
        return 1;
    }
    else if (strcmp(str, "any") == 0){
        *protocol = PROT_ANY;
        return 1;
    }
    else{
        printf("Error converting protocol string to protocol number: not a valid protocol\n");
        return 0;
    }
}


// This function converts an ack string to an ack_t enum.
static int convert_string_to_ack(char *str, ack_t *ack){
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


// This function converts an action string to an action.
static int convert_string_to_action(char *str, uint8_t *action){
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

static int load_rules(const char *rule_db_file_path){
    rule_t rules[MAX_RULES];
    FILE *fp;
    char line[256];
    uint8_t lines_read = 0;
    fp = fopen(rule_db_file_path, "r");
    if (fp == NULL){
        printf("Error opening file!\n");
        return -1;
    }
    // Read the file line by line and convert each line to a rule struct and save it in the rules array.
    while (fgets(line, sizeof(line), fp) != NULL){
        printf("read the #%i line: %s\n", lines_read, line);
        if (convert_string_to_rule(line, rules + lines_read) == -1){
            printf("Error converting string to rule\n");
            return -1;
        }
        lines_read++;
        }
    fclose(fp);
    return 0;
}