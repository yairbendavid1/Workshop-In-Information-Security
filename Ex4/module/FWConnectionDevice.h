#ifndef _FW_CONNECTION_DEVICE_H
#define _FW_CONNECTION_DEVICE_H 

ssize_t show_connections(struct device *dev, struct device_attribute *attr, char *buf);
unsigned int check_for_syn_packet(struct sk_buff *skb, const struct nf_hook_state *state);
direction_t next_direction(direction_t direction);
void *insert_connection(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, direction_t direction);
void finish_connection(connection_t *conn);
void set_entities(__be32 *src_ip, __be16 *src_port, __be32 *dst_ip, __be16 *dst_port, direction_t direction, entity_t *int_entity, entity_t *out_entity);
int compare_entities(entity_t *entity1, entity_t *entity2);
connection_t *is_connection_exist(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, direction_t direction);
void convert_connection_to_buff(connection_t *conn, char *buf);
// Structure for a connection, used in the connection table which is a linked list.

typedef struct
{
    __be32 ip;
    __be16 port;
} entity_t;

// Those are the states of the TCP state machine.
// We will use those to check if the connection is valid or not.
typedef enum
{
    PRESYN,
    SYN,
    SYN_ACK,
    ESTABLISHED,
    A_SENT_FIN,
    A_FIN_B_ACK,
    A_FIN_B_FIN,
    A_FIN_B_FIN_ACK,
    A_FIN2,
    B_FIN2,
    B_ACK,
} tcp_status_t;

// This is a state of a TCP connection.
// we will use state machine to check validity of transitions.
// we will use this state to check if the connection is valid or not.
// we do need the direction, since we store only one connection for both directions,
// so use the direction to know which direction we are in so we can update the state accordingly.
typedef struct
{
    tcp_status_t status;
    direction_t direction;
} tcp_state_t;



// This is a connection entry in the connection table.
typedef struct
{
    entity_t intity;  // entity in the internal network
    entity_t outity;  // entity in the external network
    tcp_state_t state; // the state of the connection

    struct list_head node; // the node in the linked list - used to iterate over the list
} connection_t; 



#endif // _FW_CONNECTION_DEVICE_H