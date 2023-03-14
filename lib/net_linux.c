#include "net.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

typedef struct tcp_connection {
  int listenSockFD;   // Optional, only required if tcp_listen is called.
  int *dataFDs;     // One filedescriptor for each successful connection we establish
  size_t numDataFDs;
  conn_opt options;
  int uid;          // Unique ID for this identifier object.
                    // A value of -1 denotes this slot in activeConnections 
                    // is free.
} tcp_connection;

tcp_connection activeConnections[MAX_CONNECTION_OBJECTS];
size_t connObjects = 0;
int nextUID = 0;

typedef struct udp_connection {
  // TODO
} udp_connection;

typedef struct remote_ip {
  int protocolVer;
  union {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
  } ipData;
} remote_ip;

// Private functions, for internal use only, not exposed to the external API
int generate_listen_socket() {
  // TODO
}

int Initialize() {
  // Initialize all slots to unused.
  for (int i = 0; i < MAX_CONNECTION_OBJECTS; i++) {
    activeConnections[i].uid = -1;
    activeConnections[i].listenSockFD = -1;
    activeConnections[i].numDataFDs = 0;
  }
}

void free_sock_addresses(remote_ips ips) {
  free(ips.ips);
}

remote_ips process_tcp_sock_addresses(tcp_connection *conn, char **ips, char **ports, int len) {
  remote_ips ipList = {0};
  ipList.ips = malloc(sizeof(remote_ip) * len);

  int rc = -1;
   for (int i = 0; i < len; i++) {
      struct addrinfo *res = NULL;
      struct addrinfo hints = {0};

      hints.ai_socktype = SOCK_STREAM;
      // query the connection to get the requested IP version.
      switch (conn->options.ver) {
        case IPV4:
          hints.ai_family = AF_INET;
          break;
        case IPV6:
          hints.ai_family = AF_INET6;
          break;
        case DONT_CARE:
        default:
          hints.ai_family = AF_UNSPEC;
          break;
      }
      
      // Get address info for each requested ip/port combination.
      if ((rc = getaddrinfo(ips[i], ports[i], &hints, &res)) == 0) {
        // Got a linked list of candidate addresses
        struct addrinfo *candidate = NULL;
        for (candidate = res; candidate != NULL; candidate = candidate->ai_next) {
          if (candidate->ai_protocol != IPPROTO_TCP) { continue; }
          if (candidate->ai_socktype != SOCK_STREAM) { continue; }
          // We need to copy the sockaddr_in into our new array buffer,
          // since we are going to free the linked list we got from the OS 
          // at the end of this function call.
          if (candidate->ai_family == AF_INET) {
            remote_ip ip = {0};
            ip.protocolVer = AF_INET;
            memcpy(&ip.ipData.ipv4, (struct sockaddr_in*)candidate->ai_addr, sizeof(struct sockaddr_in));
            ipList.ips[ipList.len] = ip;
            ipList.len += 1;
            break;
          } else {
            remote_ip ip = {0};
            ip.protocolVer = AF_INET6;
            memcpy(&ip.ipData.ipv6, (struct sockaddr_in6*)candidate->ai_addr, sizeof(struct sockaddr_in6));
            ipList.ips[ipList.len] = ip;
            ipList.len += 1;
            break;
          }
        }
        freeaddrinfo(res);
      }
   }
   return ipList;
}

tcp_connection *create_tcp_connection(conn_opt opt) {
  for (int i = 0; i < MAX_CONNECTION_OBJECTS; i++) {
    if (activeConnections[i].uid == -1) {
      // Found a free slot
      activeConnections[i].uid = nextUID++;
      activeConnections[i].options = opt;
      return &activeConnections[i];
    }
  }
  return NULL;
}

int destroy_tcp_connection(tcp_connection *conn) {
  if (conn == NULL) { return -1; }
  conn->uid = -1; // Mark this slot as free
  
  // TODO: Close established TCP connections with remote hosts
  // and free sockets/other resources.
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

remote_ips process_udp_sock_addresses(udp_connection *conn, char **ips, char **ports, int len) {
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