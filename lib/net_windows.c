#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "net.h"

#pragma comment(lib, "ws2_32.lib")

// TODO: move to net.h
#define RECV_BUF_SIZE 64
#define PORT_STRLEN 6

typedef struct tcp_connection {
  int listenSockFD;
  int *dataFDs;
  size_t numDataFDs;
  conn_opt options;
  int uid;
} tcp_connection;

WSADATA wsaData; // contains information about the Windows Sockets implementation
tcp_connection activeConnections[MAX_CONNECTION_OBJECTS];
size_t connObjects = 0;
int nextUID = 0;

typedef struct udp_connection {
  // TODO
} udp_connection;

// typedef struct remote_ip {
//   int protocolVer;
//   union {
//     struct sockaddr_in ipv4;
//     struct sockaddr_in6 ipv6;
//   } ipData;
// } remote_ip;

typedef struct remote_ip_handle {
  int protocolVer;
  int fd;
  union {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
  } ipData;
} remote_ip_handle;

void Initialize() {
  // WSAStartup initiates use of WS2_32.dll
  int rc = WSAStartup(MAKEWORD(2,2), &wsaData);
  if (rc != 0) {
    printf("WSAStartup failed: %d\n", rc);
    return 1;
  }

  for (int i = 0; i < MAX_CONNECTION_OBJECTS; i++) {
    activeConnections[i].uid = -1;
    activeConnections[i].listenSockFD = -1;
    activeConnections[i].numDataFDs = 0;
  }
}

void free_sock_addresses(remote_ips ips) {
  // TODO
}

remote_ips process_tcp_sock_addresses(tcp_connection *conn, char **ips, char **ports, int len) {
  remote_ips ipList = {0};
  ipList.ips = malloc(sizeof(remote_ip) * len);

  int rc = -1;
  for (int i = 0; i < len; i++) {
    struct addrinfo *res = NULL, *ptr = NULL, hints = {0};

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    switch (conn->options.ver) {
    case IPV4:
      hints.ai_family = AF_INET;
      break;
    case IPV6:
      hints.ai_family = AF_INET6;
    case DONT_CARE:
    default:
      hints.ai_family = AF_UNSPEC;
      break;
    }

    // if ((rc = getaddrinfo(ips[i], ports[i], &hints, &res)) == 0) {
    //   struct addrinfo *candidate = NULL;
    //   for (candidate = res; candidate != NULL; candidate = candidate->ai_next) {
    //     remote_ip ip = {0};
    //     ip.handle = calloc(1, sizeof(remote_ip_handle));

    //     if (candidate->ai_family == AF_INET) {
    //       ip.handle->protocolVer = IPV4;
    //       memcpy(&ip.handle->ipData.ipv4, (struct sockaddr_in *)candidate->ai_addr, sizeof(struct sockaddr_in));
    //       ip.addr = malloc(INET_ADDRSTRLEN + 1);
    //     } else {
    //       ip.handle->protocolVer = IPV6;
    //       memcpy(&ip.handle->ipData.ipv6, (struct sockaddr_in6 *)candidate->ai_addr, sizeof(struct sockaddr_in6));
    //       ip.addr = malloc(INET6_ADDRSTRLEN + 1);
    //     }

    //     ip.port = malloc(PORT_STRLEN);
    //     strcpy(ip.port, ports[i]);
    //     ipList.ips[ipList.len] = ip;
    //     ipList.len++;
    //     break;
    //   }
    //   freeaddrinfo(res);
    //   WSACleanup();
    // }

    rc = getaddrinfo(ips[i], ports[i], &hints, &res);
    if (rc == 0) {
      remote_ip ip = {0};
      ip.handle = calloc(1, sizeof(remote_ip_handle));

      if (res->ai_family = AF_INET) {
        ip.handle->protocolVer = IPV4;
        memcpy(&ip.handle->ipData.ipv4, (struct sockaddr_in *)res->ai_addr, sizeof(struct sockaddr_in));
        ip.addr = malloc(INET_ADDRSTRLEN + 1);
      } else {
        ip.handle->protocolVer = IPV6;
        memcpy(&ip.handle->ipData.ipv6, (struct sockaddr_in6 *)res->ai_addr, sizeof(struct sockaddr_in6));
        ip.addr = malloc(INET6_ADDRSTRLEN + 1);
      }

      ip.port = malloc(PORT_STRLEN);
      strcpy(ip.port, ports[i]);
      ipList.ips[ipList.len] = ip;
      ipList.len++;

      freeaddrinfo(res);
      WSACleanup();
    }
  }
  return ipList;
}

tcp_connection *create_tcp_connection(conn_opt opt) {
  for (int i = 0; i < MAX_CONNECTION_OBJECTS; i++) {
    if (activeConnections[i].uid == -1) {
      activeConnections[i].uid = nextUID++;
      activeConnections[i].options = opt;
      return &activeConnections[i];
    }
  }
  return NULL;
}

int destroy_tcp_connection(tcp_connection *conn) {
  if (conn == NULL) return -1;
  conn->uid = -1;

  // TODO: close corresponding TCP connection and free allocated memory
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

// TODO: conn is not use here?
int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data,
                     size_t len) {
  // TODO: test needed
  int rc, nSent = 0;
  for (int i = 0; i < remotes.len; i++)
  {
    rc = send(remotes.ips[i].handle->fd, data, len, 0);
    if (rc > 0) {
      nSent++;
    }
  }
  return nSent;
}

int receive_tcp_message_async(tcp_connection *conn, remote_ips ips, int senderIdx, void **data, size_t *len) {
  // TODO: test needed; is user expected to free *data on failure?
  *data = malloc(RECV_BUF_SIZE);
  if (senderIdx > ips.len -1) {
    return -1;
  }

  remote_ip *sender = &ips.ips[senderIdx];

  struct timeval timeval = {0};
  timeval.tv_sec = 0;
  timeval.tv_usec = conn->options.timeout;
  fd_set singleset;

  FD_ZERO(&singleset);
  FD_SET(sender->handle->fd, &singleset);

  int res = select(sender->handle->fd + 1, &singleset, NULL, NULL, &timeval);
  if (res > 0 && FD_ISSET(sender->handle->fd, &singleset)) {
    return recv(sender->handle->fd, *data, RECV_BUF_SIZE, 0);
  } else {
    return 0;
  }
}

int receive_tcp_message(tcp_connection *conn, remote_ips ips, int senderIdx, void **data, size_t *len) {
  // TODO: test needed
  *data = malloc(RECV_BUF_SIZE);
  if (senderIdx > ips.len - 1) {
    return -1;
  }

  remote_ip *sender = &ips.ips[senderIdx];
  return recv(sender->handle->fd, *data, RECV_BUF_SIZE, 0);
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