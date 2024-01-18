#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yair");

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

// This function is called when the module is loaded.
// It registers the hooks at the input, forward, output points.
// If an error occurs, it unregisters all the hooks that were registered before, and returns -1 to indicate that the module failed to load

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
    return 0; // if we got here, all hooks were registered successfully!

    //if we failed to register a hook, we need to unregister all the hooks that were registered before.
    //we will do it in reverse order, so that we will unregister the hooks that were registered first, last.
    failed_output:
        nf_unregister_net_hook(&init_net, &output_hook_point_op);
    failed_forward:
        nf_unregister_net_hook(&init_net, &forward_hook_point_op);
    failed_input:
        nf_unregister_net_hook(&init_net, &input_hook_point_op);
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
// It unregisters all the hooks that were registered before.
static void __exit my_module_exit_function(void) {
	nf_unregister_net_hook(&init_net, &input_hook_point_op);
    nf_unregister_net_hook(&init_net, &forward_hook_point_op);
    nf_unregister_net_hook(&init_net, &output_hook_point_op);
}


// Register the module's init and exit functions.
module_init(my_module_init_function);
module_exit(my_module_exit_function);
