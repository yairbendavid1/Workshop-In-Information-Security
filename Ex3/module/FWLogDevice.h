#ifndef _LOG_H_
#define _LOG_H_

#include "fw.h"


void set_time_ip_and_port_for_log(log_row_t *log, __be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, __u8 *protocol);
__u8 logcmp(log_row_t *obj1, log_row_t *obj2);
void add_log(log_row_t *log, reason_t reason, unsigned char action);
ssize_t read_log(struct file *filp, char *buf, size_t length, loff_t *offp);
ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
int open_log(struct inode *_inode, struct file *_file);
void convert_log_to_buff(const log_row_t *log, char *buf);




#endif

