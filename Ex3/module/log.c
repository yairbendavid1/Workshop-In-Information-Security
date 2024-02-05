#include "fw.h"
#include "filter.h" 
#include "rule.h"
#include "log.h"


// as reference for the klist i used this medium:
// https://medium.com/@414apache/kernel-data-structures-linkedlist-b13e4f8de4bf
// it was not the only source i use but most of it is there.


// starting with defining a struct which will hold both the log and the list
typedef struct{
    // link list element which will allow us to travel within log nodes
    struct list_head klist_log_node;
    // the log itself
    log_row_t log_data;
} log_node_t;

LIST_HEAD(log_head); // This macro defines and initializes a list_head object named log_head
static __u32 log_size = 0; // The amount of log entries, will be to tell the user how many logs we have in the log list.
static __u8 sent_log_size = 0; // A flag to indicate if the log size was written to the user file buffer yet.
log_node_t current_log_on_read; // This will be used to keep track of the current log on read, so we can continue from the last log on the next read.


// This function will get data from packet and fill the log_row_t struct
// the fields will be time, ip, port and protocol.
void set_time_ip_and_port_for_log(log_row_t *log, __be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, __u8 *protocol){
    // we first start with the time field
    // we can use the getnstimeofday function to get the current time
    struct timespec time;
    getnstimeofday(&time);
    log->timestamp = time.tv_sec;

    // Now all we need is to fill the rest of the fields
    log->protocol = *protocol;
    log->src_ip = *src_ip;
    log->dst_ip = *dst_ip;
    log->src_port = *src_port;
    log->dst_port = *dst_port;
    // on log, if the packet type was not logged before, the count will be 1 on the first time.
    // so we can set the count to 1 by default, and if the packet was logged before, we will increase the count accordingly.
    log->count = 1;
}


// This function will compare two log_row_t structs and return 1 if they are the same, 0 if they are not.
// We say that two log_row_t structs are the same if the src_ip, dst_ip, src_port, dst_port, protocol and reason fields are the same.
__u8 logcmp(log_row_t *obj1, log_row_t *obj2){
    // we will compare the src_ip, dst_ip, src_port, dst_port and protocol fields
    if(obj1->src_ip == obj2->src_ip && obj1->dst_ip == obj2->dst_ip && obj1->src_port == obj2->src_port && obj1->dst_port == obj2->dst_port && obj1->protocol == obj2->protocol && obj1->reason == obj2->reason){
        return 1;
    }
    return 0;
}


// This function is called from the packet handler function every time a packet is dropped or accepted. 
// This function will get a log_row_t struct and add it to the log list
// if the log was logged before, it will increase the count field of the relevant log_row_t struct by 1.
// if the log was not logged before, it will add it to the log list.
void add_log(log_row_t *log, reason_t reason, unsigned char action){
    //first we need to set the reason and action fields
    log->reason = reason;
    log->action = action;

    // we will use the list_for_each_entry macro to iterate over the list
    // we will use the log_node_t struct to get the log_data field and compare it with the log_row_t struct
    log_node_t *entry;
    list_for_each_entry(entry, &log_head, klist_log_node){
        // we will compare the log_data field with the log_row_t struct
        if(logcmp(&entry->log_data, log)){
            // if we found a match, we need to update this log.
            // we will update the timestamp and increase the count field by 1
            struct timespec time;
            getnstimeofday(&time);
            entry->log_data.timestamp = time.tv_sec;
            entry->log_data.count++;
            return;
        }
    }
    // if we did not find a match, we will add the log_row_t struct to the list
    log_node_t *new_log = kmalloc(sizeof(log_node_t), GFP_KERNEL);
    new_log->log_data = *log;
    list_add_tail(&new_log->klist_log_node, &log_head);
    log_size++;
}


// This function is the "store" in the sysfs log device.
// On call, it will reset the log list, making it empty.
ssize_t reset_log(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    log_node_t *entry, *tmp;
    // we will use the list_for_each_entry_safe macro to iterate over the list and delete all the nodes
    list_for_each_entry_safe(entry, tmp, &log_head, klist_log_node){
        // we will delete the node and free the memory
        list_del(&entry->klist_log_node);
        kfree(entry);
    }
    log_size = 0;
    return count;
}



// This function is the "open" function in the log char device.
// it will set 2 flags to zero:
// 1. sent_log_size - a flag to indicate if the log size was written to the user file buffer yet.
// 2. current_log_on_read - a flag to indicate the current log on read, so we can continue from the last log on the next read.
int open_log(struct inode *inode, struct file *filp){
    // we will set the flags to 0 and 
    sent_log_size = 0;
    current_log_on_read = NULL;
    return 0;
}



// This function is the "read" function in the log char device.
// it will convert each rule to a simple buffer and write it to the user file buffer.
// the buffer will be in the following format:
// [timestamp, protocol, action, src_ip, dst_ip, src_port, dst_port, reason, count]
// the function will return the amount of bytes written to the user file buffer.
ssize_t read_log(struct file *filp, char *buf, size_t length, loff_t *offp){
    // we will use the log_node_t struct to get the log_data field and convert it to a buffer
    log_node_t *entry;
    int log_buff_size = sizeof(unsigned long) + sizeof(unsigned char) + sizeof(unsigned char) + sizeof(__be32) + sizeof(__be32) + sizeof(__be16) + sizeof(__be16) + sizeof(reason_t) + sizeof(unsigned int);
    char my_buf[log_buff_size];
    int count = 0;
    
    // First we need to check if the log size was written to the user file buffer yet.
    // if not,  we will write it to the user file buffer and set the flag to 1.

    if(!sent_log_size){
        // we will check if the buffer size is big enough to write the log size
        if(length < sizeof(__u32)){
            return 0;
        }
        // we will write the log size to the user file buffer
        if(copy_to_user(buf, &log_size, sizeof(__u32))){
            // if we failed to write the log size to the user file buffer, we will return an error
            return -EFAULT;
        }
        sent_log_size = 1; // we will not write the log size again
        count += sizeof(__u32); // we will increase the count by the size of the log size
        length -= sizeof(__u32); // we will decrease the length by the size of the log size
        buf += sizeof(__u32); // we will increase the buffer address by the size of the log size
    }

    // Now, if the length is not enough to write the log, we will return the count.
    if(length < log_buff_size){
        return count;
    }

    // we need to continue from the last log that was read.
    // we will use the current_log_on_read flag to continue from the last log that was read.
    if(current_log_on_read == NULL){
        current_log_on_read = list_first_entry(&log_head, log_node_t, klist_log_node);
    }
    else{
        current_log_on_read = list_next_entry(current_log_on_read, klist_log_node);
    }

    // we will use the list_for_each_entry macro to iterate over the list and convert each log to a buffer
    list_for_each_entry_from(current_log_on_read, entry, &log_head, klist_log_node){
        // we will convert the log to a buffer
        convert_log_to_buff(&entry->log_data, my_buf);
        // we will check if the buffer size is big enough to write the log to the user file buffer
        if(length < log_buff_size){
            return count;
        }
        // we will write the log to the user file buffer
        if(copy_to_user(buf, my_buf, log_buff_size)){
            // if we failed to write the log to the user file buffer, we will return an error
            return -EFAULT;
        }
        count += log_buff_size; // we will increase the count by the size of the log
        length -= log_buff_size; // we will decrease the length by the size of the log
        buf += log_buff_size; // we will increase the buffer address by the size of the log
    }
    return count;
}


// This function will convert a log_row_t struct to a buffer
// the buffer will be in the following format:
// timestamp, protocol, action, src_ip, dst_ip, src_port, dst_port, reason, count
void convert_log_to_buff(log_row_t *log, char *buf){
    copy_to_buff_and_increase(&log->timestamp, &buf, sizeof(unsigned long));
    copy_to_buff_and_increase(&log->protocol, &buf, sizeof(unsigned char));
    copy_to_buff_and_increase(&log->action, &buf, sizeof(unsigned char));
    copy_to_buff_and_increase(&log->src_ip, &buf, sizeof(__be32));
    copy_to_buff_and_increase(&log->dst_ip, &buf, sizeof(__be32));
    copy_to_buff_and_increase(&log->src_port, &buf, sizeof(__be16));
    copy_to_buff_and_increase(&log->dst_port, &buf, sizeof(__be16));
    copy_to_buff_and_increase(&log->reason, &buf, sizeof(reason_t));
    copy_to_buff_and_increase(&log->count, &buf, sizeof(unsigned int));
}


/*

typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

*/