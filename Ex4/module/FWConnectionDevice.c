#include "fw.h"
#include "FWConnectionDevice.h"


LIST_HEAD(connection_table);
__u32 connection_table_size = 0


// This function check if the packet is a syn packet
unsigned int check_for_syn_packet(struct sk_buff *skb, const struct nf_hook_state *state){
    struct tcphdr *tcph = tcp_hdr(skb);
    if (tcph->syn && !tcph->ack){
        return 1;
    }
    return 0;

}

// This function will return the next direction according to the current direction
direction_t next_direction(direction_t direction){
    if (direction == DIRECTION_IN){
        return DIRECTION_OUT;
    }
    return DIRECTION_IN;
}

// This function will add a new connection to the connection table
void *insert_connection(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, direction_t direction){
    connection_t *conn;
    conn = kmalloc(sizeof(connection_t), GFP_KERNEL);
    if (!conn){
        return NULL;
    }
    if (direction == DIRECTION_IN){
        conn->intity.ip = *dst_ip;
        conn->intity.port = *dst_port;
        conn->outity.ip = *src_ip;
        conn->outity.port = *src_port;
    }
    else{
        conn->intity.ip = *src_ip;
        conn->intity.port = *src_port;
        conn->outity.ip = *dst_ip;
        conn->outity.port = *dst_port;
    }
    conn->state.status = SYN;
    conn->state.direction = next_direction(direction);
    list_add(&conn->node, &connection_table);
    connection_table_size++;

}


// This function will set the in and out entities according to the direction
// if the direction is in, the in entity will be the destination and the out entity will be the source
void set_entities(__be32 *src_ip, __be16 *src_port, __be32 *dst_ip, __be16 *dst_port, direction_t direction, entity_t *int_entity, entity_t *out_entity){
    if (direction == DIRECTION_IN){
        int_entity->ip = *dst_ip;
        int_entity->port = *dst_port;
        out_entity->ip = *src_ip;
        out_entity->port = *src_port;
    }
    else{
        int_entity->ip = *src_ip;
        int_entity->port = *src_port;
        out_entity->ip = *dst_ip;
        out_entity->port = *dst_port;
    }
}


// This function will compare two entities and return 1 if they are equal and 0 if they are not
// if one of the ports is 0, it means any port so it considered as equal
int compare_entities(entity_t *entity1, entity_t *entity2){

    if (entity1->ip == entity2->ip && (entity1->port == entity2->port || entity1->port == 0 || entity2->port == 0)){
        return 1;
    }
    return 0;
}

// This function check if exist connection in the connection table with the same credentials
connection_t *is_connection_exist(__be32 *src_ip, __be32 *dst_ip, __be16 *src_port, __be16 *dst_port, direction_t direction){
    connection_t *conn;
    entity_t int_entity, out_entity;
    // extract the in and out entities from the packet using the direction
    set_entities(src_ip, src_port, dst_ip, dst_port, direction, &int_entity, &out_entity);

    // we will iterate over the connection table and check if there is a connection with the same credentials
    // if we find one, we will return it, otherwise we will return NULL
    list_for_each_entry(conn, &connection_table, node)
    {
        if (compare_entities(&conn->intity, &int_entity) && compare_entities(&conn->outity, &out_entity)){
            return conn;
        }
    }
    return NULL;  
}

// This function is called when the device file is read from user space.
// It should return the number of bytes written to the buffer.
ssize_t show_connections(struct device *dev, struct device_attribute *attr, char *buf)
{
    connection_t *conn;
    ssize_t csize;

    VAR2BUF(connections_amount);

    list_for_each_entry(conn, &ctable, list_node)
    {
        conn2buf(conn, buf);
        buf += CONN_BUF_SIZE;
    }
    con_size = sizeof(connections_size) + connections_size * CONN_BUF_SIZE;
    buf += con_size;
    return con_size;
}



ssize_t ctable2buf(char *buf)
{
    connection_t *conn;

    VAR2BUF(connections_amount);

    list_for_each_entry(conn, &ctable, list_node)
    {
        conn2buf(conn, buf);
        buf += CONN_BUF_SIZE;
    }

    return CAMOUNT_SIZE + connections_amount * CONN_BUF_SIZE;
}
