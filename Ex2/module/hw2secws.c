#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <linux/device.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yair");



// sysfs informatiom pointers and variables 
static struct file_operations fops = {
	.owner = THIS_MODULE
};
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;


// We need counters for how many packets were accepted and how many were dropped.
// We will use these counters to display the statistics in the sysfs file.
static unsigned int accepted_packets_cnt = 0;
static unsigned int droped_packets_cnt = 0;

// We need 3 hook points, one for each of the following: input, forward, output.
// We will accept all packets that are hooked in the input and output points, 
// and drop all packets that are hooked in the forward point.
// start by allocating 3 structs to hold hook operations. 

static struct nf_hook_ops input_hook_point_op;         // input hook point op
static struct nf_hook_ops forward_hook_point_op;        // forward hook point op
static struct nf_hook_ops output_hook_point_op;     // output hook point op


/* -----------  functions declarations -------------*/

static int initiate_hook_point(struct nf_hook_ops *my_op, enum nf_inet_hooks hook_point_type); // This function registers a hook at the given hook point.
static unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state); // This function is called when a packet is received at one of the hook points.
static int __init my_module_init_function(void);   // This function is called when the module is loaded.
static void __exit my_module_exit_function(void);  // This function is called when the module is unloaded.





// The display function is called when the sysfs file is read.
// It will display the statistics of the packets that were accepted and dropped.
// The format of the statistics is: "accepted_packets_cnt,droped_packets_cnt\n"
ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u,%u\n", accepted_packets_cnt, droped_packets_cnt);
}


// The modify function is called when the sysfs file is written.
// It will reset the statistics of the packets that were accepted and dropped.
// if the first char in the buffer is 'r', the statistics will be reset.
// This way, we can reset the statistics by writing 'r' to the sysfs file from the user space. 
ssize_t reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	char temp;
    if (sscanf(buf, "%c", &temp) == 'r')
        accepted_packets_cnt = 0;
        droped_packets_cnt = 0;
	return count;	
}

// This is the sysfs attribute that will be created.
static DEVICE_ATTR(sysfs_att, S_IWUSR | S_IRUGO , display, reset);



static int __init my_module_init_function(void) {
	// on init, we want to register the hooks at the input, forward, output points.
    if(initiate_hook_point(&input_hook_point_op, NF_INET_LOCAL_IN) != 0) { // register the hook at the input point and check for errors
        printk(KERN_INFO "Error on setting netfilter INPUT hook point\n");
        goto failed_input;
    }
    if(initiate_hook_point(&forward_hook_point_op, NF_INET_FORWARD) != 0) { // register the hook at the forward point and check for errors
        printk(KERN_INFO "Error on setting netfilter FORWARD hook point\n");
        goto failed_forward;
    }
    if(initiate_hook_point(&output_hook_point_op, NF_INET_LOCAL_IN) != 0) { // register the hook at the output point and check for errors
        printk(KERN_INFO "Error on setting netfilter OUTPUT hook point\n");
        goto failed_output;
    }
    

    // Moving to sysfs class and device creation part    


    // Create char device with the name "packet_statistics"
	major_number = register_chrdev(0, "packet_statistics", &fops); //register_chrdev returns the major number of the newly created device "packet_statistics".
	if (major_number < 0){  goto chrdev_creation_failed; }   //if the major number is negative, the device creation failed. 


	// Create sysfs class with the name "Sysfs_class"
	sysfs_class = class_create(THIS_MODULE, "Sysfs_class"); //class_create returns a pointer to the newly created class "Sysfs_class".
	if (IS_ERR(sysfs_class)) { goto sysfs_class_creation_failed ; } //if an error occured, move to the error section.
      
	
	//create sysfs device 
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "packet_statistics");	
	if (IS_ERR(sysfs_device)) { goto sysfs_device_creation_failed; } //if an error occured, move to the error section0
	
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr)) // device_create_file returns 0 if the file was created successfully.
	{
		goto file_attr_creation_failed; //if an error occured, move to the error section.
	}
    
    return 0; // if we got here, all hooks were registered  and all sysfs files were created successfully!


// if we failed to register hook or create sysfs files, we need to unregister all the hooks that were registered before and destroy the sysfs files that were created before.
// we will do it in reverse order, so that we will unregister the hooks that were registered first, last.
    
    
file_attr_creation_failed:
    device_destroy(sysfs_class, MKDEV(major_number, 0));
sysfs_device_creation_failed:
    class_destroy(sysfs_class);
sysfs_class_creation_failed:
    unregister_chrdev(major_number, "packet_statistics");
chrdev_creation_failed:
    nf_unregister_net_hook(&init_net, &output_hook_point_op);
failed_output:
    nf_unregister_net_hook(&init_net, &forward_hook_point_op);
failed_forward:
    nf_unregister_net_hook(&init_net, &input_hook_point_op);
failed_input:
    return -1; // return -1 to indicate that the module failed to load. 
}



// This function registers a hook at the given hook point.
// It returns 0 if the hook was registered successfully, and -1 otherwise.
static int initiate_hook_point(struct nf_hook_ops *my_op, enum nf_inet_hooks hook_point_type) {
    my_op->pf = PF_INET;    //this indicates that we are interested in IPv4 packets
    my_op->hook = (nf_hookfn*) Handle_Packet;    // set the hook function to be Handle_Packet
    my_op->hooknum = hook_point_type;                 // the protocol specific hook type identifier.
    my_op->priority = NF_IP_PRI_FIRST;       // max hook priority
    
    return nf_register_net_hook(&init_net, my_op);  // register the hook and return the error code. 0 if no error.
}




// This function is called when a packet is received at one of the hook points.
// It will Accept all packets that are hooked in the input and output points,
// and drop all packets that are hooked in the forward point.
static unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
   if(state->hook == NF_INET_LOCAL_IN || state->hook == NF_INET_LOCAL_OUT) {
       printk(KERN_INFO "*** Packet Accepted ***\n");
       return NF_ACCEPT;
   }
   else if(state->hook == NF_INET_FORWARD) {
       printk(KERN_INFO "*** Packet Dropped ***\n");
       return NF_DROP;
   }
   else {
       printk(KERN_INFO "The packet is not hooked in \n");
       return NF_ACCEPT;
   }
}





// This function is called when the module is unloaded.
// It unregisters all the hooks that were registered before and destroys the sysfs files that were created before.
static void __exit my_module_exit_function(void) {
    device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "packet_statistics");
	nf_unregister_net_hook(&init_net, &input_hook_point_op);
    nf_unregister_net_hook(&init_net, &forward_hook_point_op);
    nf_unregister_net_hook(&init_net, &output_hook_point_op);
}


// Register the module's init and exit functions.
module_init(my_module_init_function);
module_exit(my_module_exit_function);

