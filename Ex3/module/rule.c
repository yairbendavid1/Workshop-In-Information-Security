#include "fw.h"
#include "rule.h"
#include "log.h"
#include "filter.h"




static rule_table_t current_rule_set = {.valid = 0}; // The current rule that we will use for filtering


// Since we want to use the rule table in the filter module, we will define getters for the rule table.

// This function will return the current rule table.
rule_t *get_rule_table(void){
    return current_rule_set.rule_table;
}


// This function will return the current rule table amount.
__u8 get_rules_amount(void){
    return current_rule_set.amount;
}


// This function will return if the current rule table is valid.
int is_valid_table(void){
    return current_rule_set.valid;
}




// This function will be the fw_rules "show" function.
// On show rules command, the user will read from the rules device all the rules buffer, and this function will be called.
// This function will convert all the rules to a buffer and return it to the user.
ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf){
    int i;
    __u8 size_of_kernel_buff;
    __u8 rules_amount;
    ssize_t cnt;
    // If the rule set is not valid, we will write 0 and return.
    if (current_rule_set.valid == 0 || current_rule_set.amount == 0)
    {
      rules_amount = 0;
      copy_to_buff_and_increase(&buf, &rules_amount, sizeof(rules_amount));
      cnt += sizeof(rules_amount); // Increase the cnt by the rules amount size
      return cnt;
    }

    // First we will write the rules amount to the buffer
    size_of_kernel_buff = 20 + sizeof(direction_t) + sizeof(__be32) + sizeof(__be32) + sizeof(__u8) + sizeof(__be32) + sizeof(__be32) + sizeof(__u8) + sizeof(__be16) + sizeof(__be16) + sizeof(__u8) + sizeof(ack_t) + sizeof(__u8);
    cnt = 0; // The amount of bytes we wrote to the buffer
    rules_amount = current_rule_set.amount;
    copy_to_buff_and_increase(&buf, &rules_amount, sizeof(rules_amount));
    cnt += sizeof(rules_amount); // Increase the cnt by the rules amount size

    // We will write all the rules to the buffer
    for (i = 0; i < rules_amount; i++)
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
// on error, we will keep the old rule table.
ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    int i;
    __u8 size_of_kernel_buff;
    rule_table_t new_rule_set = {.valid = 0}; // The new rule that we will use for filtering
    size_of_kernel_buff = 20 + sizeof(direction_t) + sizeof(__be32) + sizeof(__be32) + sizeof(__u8) + sizeof(__be32) + sizeof(__be32) + sizeof(__u8) + sizeof(__be16) + sizeof(__be16) + sizeof(__u8) + sizeof(ack_t) + sizeof(__u8);
    // First we will read the rules amount from the buffer
    __u8 rules_amount = 0;
    copy_from_buff_and_increase(&buf, &rules_amount, sizeof(rules_amount));
    // Check if the rules amount is not bigger than the max rules
    if (rules_amount > MAX_RULES)
    {
        return count;
    }
    //
    // // Check if the buffer size is valid ( the buffer size should be the rules amount * rule size + the rules amount size)
    // if (count >= (rules_amount * size_of_kernel_buff + sizeof(rules_amount)))
    // {
    //     return count;
    // }
    new_rule_set.amount = rules_amount; // Update the new rule set amount
    // We will read all the rules from the buffer and store them in the rule_table

    for (i = 0; i < rules_amount; i++)
    {
        rule_t *rule = &new_rule_set.rule_table[i];
        create_rule_from_buff(rule, buf); // Convert the buffer to a rule
        buf += size_of_kernel_buff; // Increase the buffer address to the next rule

        // if (check_rule_format(rule) == -1) // Check if the rule is valid
        // {
        //     return count;
        // }

    }
    new_rule_set.valid = 1; // Mark the new rule set as valid

    current_rule_set = new_rule_set; // Update the current rule set
    return count;
}


static void print_rule(rule_t rule){
    rule_t *rule_ptr = &rule;
    printk("rule name: %s\n", rule_ptr->rule_name);
    printk("direction: %d\n", rule_ptr->direction);
    printk("src ip: %u\n", rule_ptr->src_ip);
    printk("src prefix mask: %u\n", rule_ptr->src_prefix_mask);
    printk("src prefix size: %u\n", rule_ptr->src_prefix_size);
    printk("dst ip: %u\n", rule_ptr->dst_ip);
    printk("dst prefix mask: %u\n", rule_ptr->dst_prefix_mask);
    printk("dst prefix size: %u\n", rule_ptr->dst_prefix_size);
    printk("src port: %u\n", rule_ptr->src_port);
    printk("dst port: %u\n", rule_ptr->dst_port);
    printk("protocol: %u\n", rule_ptr->protocol);
    printk("ack: %u\n", rule_ptr->ack);
    printk("action: %u\n", rule_ptr->action);
    printk("\n");

}


void copy_from_buff_and_increase(const char **buf_ptr, void *var, size_t n){
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
void create_rule_from_buff(rule_t *rule, const char *buf){
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

// This function will check if a rule sent from the user is valid and can be added to the rule table.
// The function will return 0 if the rule is valid, and -1 if the rule is not valid.
int check_rule_format(rule_t *rule){
    // Check if the rule name is valid
    if (strlen(rule->rule_name) > 20)
    {
        return -1;
    }

    // Check if the direction is valid
    if (rule->direction != DIRECTION_IN && rule->direction != DIRECTION_OUT && rule->direction != DIRECTION_ANY)
    {
        return -1;
    }

    // Check if the src prefix size is valid
    if (rule->src_prefix_size > 32)
    {
        return -1;
    }

    // Check if the dst prefix size is valid
    if (rule->dst_prefix_size > 32)
    {
        return -1;
    }

    // Check if the src port is valid
    if (rule->src_port > 1024)
    {
        return -1;
    }

    // Check if the dst port is valid
    if (rule->dst_port > 1024)
    {
        return -1;
    }

    // Check if the protocol is valid
    if (rule->protocol != PROT_ICMP && rule->protocol != PROT_TCP && rule->protocol != PROT_UDP && rule->protocol != PROT_OTHER && rule->protocol != PROT_ANY)
    {
        return -1;
    }

    // Check if the ack is valid
    if (rule->ack != ACK_NO && rule->ack != ACK_YES && rule->ack != ACK_ANY)
    {
        return -1;
    }

    // Check if the action is valid
    if (rule->action != 0 && rule->action != 1)
    {
        return -1;
    }

    return 0;
}
