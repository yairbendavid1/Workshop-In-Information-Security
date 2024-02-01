#include "rule.h"
#include "fw.h"



static rule_table_t current_rule_set = {.valid = 0}; // The current rule that we will use for filtering


// This function will be the fw_rules "show" function.
// On show rules command, the user will read from the rules device all the rules buffer, and this function will be called.
// This function will convert all the rules to a buffer and return it to the user.
static ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);{
    // If the rule set is not valid, we will return 0
    if (current_rule_set.valid == 0)
    {
        return 0;
    }

    // First we will write the rules amount to the buffer
    __u8 size_of_kernel_buff = 20 + sizeof(direction_t) + sizeof(__be32) + sizeof(__be32) + sizeof(__u8) +sizeof(__be32) + sizeof(__be32) + sizeof(__u8) + sizeof(__be16) + sizeof(__be16) + sizeof(__u8) + sizeof(ack_t) + sizeof(__u8);
    ssize_t cnt = 0; // The amount of bytes we wrote to the buffer
    __u8 rules_amount = current_rule_set.amount;
    copy_to_buff_and_increase(&buf, &rules_amount, sizeof(rules_amount));
    cnt += sizeof(rules_amount); // Increase the cnt by the rules amount size
    
    // We will write all the rules to the buffer
    for (int i = 0; i < rules_amount; i++)
    {
        rule_t *rule = &current_rule_set.rule_table[i];
        create_buff_from_rule(rule, buf); // Convert the rule to a buffer
        buf += size_of_kernel_buff; // Increase the buffer address to the next rule
        cnt += size_of_kernel_buff; // Increase the cnt by the rule size
    }
    // Return the buffer size
    return cnt;
}




// This function will be the fw_rules "store" function.
// On load rules command, the user will write to the rules device all the rules buffer, and this function will be called.
// This function will convert all the buffer to rules and store all the rules in a rule_table we will use later for the firewall filtering. 
static ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    rule_table_t new_rule_set = {.valid = 0}; // The new rule that we will use for filtering
    __u8 size_of_kernel_buff = 20 + sizeof(direction_t) + sizeof(__be32) + sizeof(__be32) + sizeof(__u8) +sizeof(__be32) + sizeof(__be32) + sizeof(__u8) + sizeof(__be16) + sizeof(__be16) + sizeof(__u8) + sizeof(ack_t) + sizeof(__u8);
    
    // First we will read the rules amount from the buffer
    __u8 rules_amount = 0; 
    copy_from_buff_and_increase(&buf, &rules_amount, sizeof(rules_amount));
    
    // Check if the rules amount is not bigger than the max rules
    if (rules_amount > MAX_RULES)
    {
        return count;
    }

    // Check if the buffer size is valid ( the buffer size should be the rules amount * rule size + the rules amount size)
    if (count != (rules_amount * size_of_kernel_buff + sizeof(rules_amount)))
    {
        return count;
    }

    new_rule_set.amount = rules_amount; // Update the new rule set amount
    // We will read all the rules from the buffer and store them in the rule_table
    for (int i = 0; i < rules_amount; i++)
    {
        rule_t *rule = &new_rule_set.rule_table[i];
        create_rule_from_buff(rule, buf); // Convert the buffer to a rule
        buf += size_of_kernel_buff; // Increase the buffer address to the next rule
    }
    new_rule_set.valid = 1; // Mark the new rule set as valid

    current_rule_set = new_rule_set; // Update the current rule set
    
    return count;
}


static void print_rule(rule_t rule){
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


static void copy_from_buff_and_increase(char **buf_ptr, const void *var, size_t n){
    memcpy(var, *buf_ptr, n);
    *buf_ptr += n;
}


void copy_to_buff_and_increase(char **buf_ptr, const void *var, size_t n){
    memcpy(*buf_ptr, var, n);
    *buf_ptr += n;
}


// This function converts a buffer that was sent from the kernel module to a rule struct.
// The format of the buffer is:
// <rule_name> <direction> <src_ip> <src_prefix_mask> <src_prefix_size> <dst_ip> <dst_prefix_mask> <dst_prefix_size> <src_port> <dst_port> <protocol> <ack> <action>
static void create_rule_from_buff(const rule_t *rule, char *buf){
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



// This function converts a rule struct to a buffer that can be sent to the kernel module.
// The format of the buffer is:
// <rule_name> <direction> <src_ip> <src_prefix_mask> <src_prefix_size> <dst_ip> <dst_prefix_mask> <dst_prefix_size> <src_port> <dst_port> <protocol> <ack> <action>
static void create_buff_from_rule(const rule_t *rule, char *buf){
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
