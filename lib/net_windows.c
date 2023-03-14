#include "net.h"

typedef struct tcp_connection {
  // TODO
} tcp_connection;

typedef struct udp_connection {
  // TODO
} udp_connection;

typedef struct remote_ip {
  // TODO
} remote_ip;

int Initialize() {
  // TODO
}

remote_ips create_ip_struct(char **ips) {
  // TODO
}

tcp_connection *create_tcp_connection(conn_opt opt) {
  // TODO
}

int destroy_tcp_connection() {
  // TODO
}

remote_ip *tcp_listen(tcp_connection *conn) {
  // TODO
}

int tcp_connect_remote(tcp_connection *conn, remote_ips remotes) {
  // TODO
}

remote_ips *tcp_active_connections(tcp_connection *conn) {
  // TODO
}

int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data,
                     size_t len) {
  // TODO
}

int receive_tcp_message_async(tcp_connection *conn, void **data, size_t *len) {
  // TODO
}

int receive_tcp_message(tcp_connection *conn, void **data, size_t *len) {
  // TODO
}

udp_connection *create_udp_connection(conn_opt opt) {
  // TODO
}

int destroy_udp_connection() {
  // TODO
}

int send_udp_message(udp_connection *conn, remote_ips remotes, void *data,
                     size_t len) {
  // TODO
}

remote_ip *receive_udp_message_async(udp_connection *conn, void **data,
                                     size_t *len) {
  // TODO
}

remote_ip *receive_udp_message(udp_connection *conn, void **data, size_t *len) {
  // TODO
}