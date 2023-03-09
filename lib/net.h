#ifndef __API_H__
#define __API_H__

#include "stddef.h"
#include "stdint.h"

enum IPVersion {
    IPV4,
    IPV6,
    DONT_CARE
};

typedef struct conn_opt {
    enum IPVersion ver;
    size_t timeout;
    uint16_t port_num;
} conn_opt;

struct tcp_connection;
typedef struct tcp_connection tcp_connection;
struct udp_connection;
typedef struct udp_connection udp_connection;
struct remote_ip;
typedef struct remote_ip remote_ip;

typedef struct remote_ips {
    remote_ip *ips; 
    size_t len;
} remote_ips;

int Initialize();

remote_ips create_ip_struct(char **ips);


tcp_connection *create_tcp_connection(conn_opt opt);
tcp_connection *destroy_tcp_connection();
int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data, size_t len);
int receive_tcp_message_async(tcp_connection *conn, void **data, size_t *len);
int receive_tcp_message(tcp_connection *conn, void **data, size_t *len);

udp_connection *create_udp_connection(conn_opt opt);
udp_connection *destroy_udp_connection();
int send_udp_message(udp_connection *conn, remote_ips remotes, void *data, size_t len);
remote_ip *receive_udp_message_async(udp_connection *conn, void **data, size_t *len);
remote_ip *receive_udp_message(udp_connection *conn, void **data, size_t *len);

#endif