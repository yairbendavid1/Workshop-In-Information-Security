#ifndef _RULE_H_
#define _RULE_H_
#include "fw.h"

ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
void create_buff_from_rule(const rule_t *rule, char *buf);
void create_rule_from_buff(rule_t *rule, const char *buf);
void copy_to_buff_and_increase(char **buf, const void *var, size_t n);
void copy_from_buff_and_increase(const char **buf, void *var, size_t n);
// static void print_rule(rule_t *rule);

rule_t *get_rule_table(void);
__u8 get_rules_amount(void);
int is_valid_table(void);
int check_rule_format(rule_t *rule);
static void print_rule(rule_t rule);

#endif
