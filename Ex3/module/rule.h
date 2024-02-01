#include "fw.h"

static ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t store_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static void create_buff_from_rule(rule_t *rule, char *buf);
static void create_rule_from_buff(rule_t *rule, const char *buf);
static void copy_to_buff_and_increase(char **buf, void *var, size_t n);
static void copy_from_buff_and_increase(const char **buf, void *var, size_t n);
static void print_rule(rule_t *rule);