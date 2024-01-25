#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yair");

// We need to create two devices, one for the rules and one for the log.
// Then, we want to assign those to the same sysfs class.
// Thus, we need to create a class, and then create the devices and assign each of them to the class.

static int rules_major_number;
static int log_major_number;
static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* log_device = NULL;

// Allocating one hook point for forwarding hook point
static struct nf_hook_ops forward_hook_point_op;




/* -----------  functions declarations -------------*/

static int initiate_hook_point(struct nf_hook_ops *my_op, enum nf_inet_hooks hook_point_type); // This function registers a hook at the given hook point.
static unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state); // This function is called when a packet is received at one of the hook points.
static int __init my_module_init_function(void);   // This function is called when the module is loaded.
static void __exit my_module_exit_function(void);  // This function is called when the module is unloaded.

/* -----------  functions implementations -------------*/


// Setting up the hook point and registering it.


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
static unsigned int Handle_Packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
   return NF_ACCEPT;
}



// With the log char device, we want to use our own implementation of the open and read functions. 
static struct file_operations log_ops = {.owner = THIS_MODULE, .open = open_log, .read = read_log};

// Unlike the log device, we dont really use the char device created for the rules, so we dont need to implement any functions.
static struct file_operations rules_fops = {
    .owner = THIS_MODULE
};

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, show_rules, store_rules);

static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO, NULL, reset_log);



// This function is called when the module is loaded.
// It returns 0 if the module was loaded successfully, and -1 otherwise.
// The function has four main parts:
// 1. Creating the sysfs class, "fw".
// 2. Creating the log device and assigning it to the class "fw".
// 3. Creating the rules device and assigning it to the class "fw".
// 4. Registering the farword hook point.
// If an error occured in one of the parts, the function will move to the error section and undo all the actions that were done before the error occured (in reverse order).
// If no error occured, the function will return 0.

static int __init my_module_init_function(void){
    /*
    Part 1: Creating the sysfs class, "fw".
    */
    
    sysfs_class = class_create(THIS_MODULE, "fw"); //class_create returns a pointer to the newly created class "fw".
    if (IS_ERR(sysfs_class)) { goto sysfs_class_creation_failed ; } //if an error occured, move to the error section.
    

    /*
    Part 2: Creating the log device and assigning it to the class "fw".
    */

    // Creating char device fot the log, named "fw_log".
    log_major_number = register_chrdev(0, "fw_log", &log_ops);
    if (log_major_number < 0)
    {
        goto log_char_device_creation_failed;
    }

    // Create Sysfs device for the log.
    log_device = device_create(sysfs_class, NULL, MKDEV(log_major, 0), NULL, "log");
    if (IS_ERR(log_device))
    {
        goto log_device_creation_failed;
    }

    // Create the attribute file for the log device.
    if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr))
    {
        goto log_file_creation_failed;
    }



    /*
    Part 3: Creating the rules device and assigning it to the class "fw".
    */

    // Creating char device fot the rules, named "rules".
    rules_major_number = register_chrdev(0, "rules", &rules_fops);
    if (rules_major_number < 0) {
        goto rules_char_device_creation_failed;
    }

    // Create Sysfs device for the rules.
    rules_device = device_create(sysfs_class, NULL, MKDEV(rules_major_number, 0), NULL, "rules");
    if (IS_ERR(rules_device)) {
        goto rule_device_creation_failed;
    }

    // Create the attribute file for the rules device.
    if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr)) {
        goto rules_file_creation_failed;
    }

    /*
    Part 4: Registering the farword hook point.
    */


    if (initiate_hook_point(&forward_hook_point_op, NF_INET_FORWARD) != 0) {
        printk(KERN_INFO "Error on setting netfilter FORWARD hook point\n");
        goto registeration_failed;
    }

    // If we got here, we successfully created the sysfs class, the log device, the rules device and registered the hook point. 
    return 0;

    
// Error section: undo all the actions that were done before the error occured (in reverse order), then return -1 to indicate that the module failed to load.
registeration_failed:
    device_remove_file(rules_dev, (const struct device_attribute *)&dev_attr_rules.attr);
rules_file_creation_failed
    device_destroy(sysfs_class, MKDEV(rules_major_number, 0));
rules_device_creation_failed:
    unregister_chrdev(rules_major_number, "rules");
rules_char_device_creation_failed:
    device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
log_file_creation_failed:
    device_destroy(sysfs_class, MKDEV(log_major_number, 0));
log_device_creation_failed:
    unregister_chrdev(log_major_number, "fw_log");
log_char_device_creation_failed:
    class_destroy(sysfs_class);
sysfs_class_creation_failed:
    return -1;
}

static int __exit my_module_exit_function(void){
    nf_unregister_net_hook(&init_net, &nf_forward_op);
    device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
    device_destroy(sysfs_class, MKDEV(log_major_number, 0));
    unregister_chrdev(log_major_number, MAJOR_NAME_LOG);
    device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
    device_destroy(sysfs_class, MKDEV(rules_major_number, 0));
    unregister_chrdev(rules_major_number, MAJOR_NAME_RULE);
}

module_init(my_module_init_function);
module_exit(my_module_exit_function);