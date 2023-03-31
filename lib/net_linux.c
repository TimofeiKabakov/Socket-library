#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "net.h"

#define RECV_BUF_SIZE 64

typedef struct tcp_connection {
  int listenSockFD;  // Optional, only required if tcp_listen is called.
  int *incomingFDs;  // One filedescriptor for each incoming connection through
                     // accept
  size_t numIncomingFDs;
  size_t maxIncomingFDs;
  int *outgoingFDs;  // One filedescriptor for each outgoing connection through
                     // connect
  size_t numOutgoingFDs;
  size_t maxOutgoingFDs;
  conn_opt options;
  int uid;  // Unique ID for this identifier object.
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
  int fd;
  union {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
  } ipData;
} remote_ip;


int compare_addr(struct sockaddr_in *first, struct sockaddr_in *second) {
  return (first->sin_addr.s_addr == second->sin_addr.s_addr) &&
         (first->sin_port == second->sin_port);
}

int compare_addr6(struct sockaddr_in6 *first, struct sockaddr_in6 *second) {
  int match = 1;
  for (int i = 0; i < 4; i++) {
    if (first->sin6_addr.__in6_u.__u6_addr32[i] !=
        second->sin6_addr.__in6_u.__u6_addr32[i]) {
      match = 0;
      break;
    }
  }

  if (first->sin6_port == second->sin6_port) {
    match = 0;
  }
  return match;
}

// Private functions, for internal use only, not exposed to the external API
int generate_socket(remote_ip ip, int listen, int doBind) {
  int protocol = ip.protocolVer == IPV4 ? AF_INET : AF_INET6;
  struct addrinfo hints = {0};
  struct addrinfo *res = NULL;
  hints.ai_family = protocol;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = listen != 0 ? AI_PASSIVE : 0;

  if (listen != 0) {
    int rc = -1;
    char portStr[6];
    sprintf(portStr, "%d", listen);
    if ((rc = getaddrinfo(NULL, portStr, &hints, &res)) != 0) {
      return -1;
    }
  } else {
    int rc = -1;
    if ((rc = getaddrinfo(NULL, "0", &hints, &res)) != 0) {
      return -1;
    }
  }

  // Got a linked list of candidate addresses
  struct addrinfo *candidate = NULL;
  for (candidate = res; candidate != NULL; candidate = candidate->ai_next) {
    if (candidate->ai_protocol != IPPROTO_TCP) {
      continue;
    }
    if (candidate->ai_socktype != SOCK_STREAM) {
      continue;
    }
    if (protocol == IPV4) {
      if (candidate->ai_family != AF_INET) {
        continue;
      }
    }
    if (protocol == IPV6) {
      if (candidate->ai_family != AF_INET6) {
        continue;
      }
    }

    int candidateSocket = 0;
    if ((candidateSocket = socket(candidate->ai_family, candidate->ai_socktype,
                                  candidate->ai_protocol)) != -1) {
      int rc = 0;
      // DEBUG
      int yes = 1;
      setsockopt(candidateSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
      if (doBind) {
        if ((rc = bind(candidateSocket, candidate->ai_addr,
                       candidate->ai_addrlen)) != -1) {
          return candidateSocket;
        }
      } else {
        return candidateSocket;
      }
      close(candidateSocket);
    }
  }
  return -1;
}

int generate_listen_socket(int ver, int portNum) {
  remote_ip ip;
  ip.protocolVer = ver;
  return generate_socket(ip, portNum, 1);
}

void Initialize() {
  // Initialize all slots to unused.
  for (int i = 0; i < MAX_CONNECTION_OBJECTS; i++) {
    activeConnections[i].uid = -1;
    activeConnections[i].listenSockFD = -1;
    activeConnections[i].numIncomingFDs = 0;
    activeConnections[i].numOutgoingFDs = 0;
  }
}

void free_sock_addresses(remote_ips ips) { free(ips.ips); }

remote_ips process_tcp_sock_addresses(tcp_connection *conn, char **ips,
                                      char **ports, int len) {
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
        hints.ai_family = AF_INET;
        break;
    }

    // Get address info for each requested ip/port combination.
    if ((rc = getaddrinfo(ips[i], ports[i], &hints, &res)) == 0) {
      // Got a linked list of candidate addresses
      struct addrinfo *candidate = NULL;
      for (candidate = res; candidate != NULL; candidate = candidate->ai_next) {
        if (candidate->ai_protocol != IPPROTO_TCP) {
          continue;
        }
        if (candidate->ai_socktype != SOCK_STREAM) {
          continue;
        }
        // We need to copy the sockaddr_in into our new array buffer,
        // since we are going to free the linked list we got from the OS
        // at the end of this function call.
        if (candidate->ai_family == AF_INET) {
          remote_ip ip = {0};
          ip.protocolVer = IPV4;
          memcpy(&ip.ipData.ipv4, (struct sockaddr_in *)candidate->ai_addr,
                 sizeof(struct sockaddr_in));
          ipList.ips[ipList.len] = ip;
          ipList.len += 1;
          break;
        } else {
          remote_ip ip = {0};
          ip.protocolVer = IPV6;
          memcpy(&ip.ipData.ipv6, (struct sockaddr_in6 *)candidate->ai_addr,
                 sizeof(struct sockaddr_in6));
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
      if (opt.ver == DONT_CARE) {
        // Default to IPV4
        activeConnections[i].options.ver = IPV4;
      }
      activeConnections[i].incomingFDs = malloc(sizeof(int) * 10);
      activeConnections[i].maxIncomingFDs = 10;
      activeConnections[i].outgoingFDs = malloc(sizeof(int) * 10);
      activeConnections[i].maxOutgoingFDs = 10;
      activeConnections[i].listenSockFD =
          generate_listen_socket(activeConnections[i].options.ver,
                                 activeConnections[i].options.port_num);
      if (activeConnections[i].listenSockFD == -1) {
        return NULL;
      }
      return &activeConnections[i];
    }
  }
  return NULL;
}

int destroy_tcp_connection(tcp_connection *conn) {
  if (conn == NULL) {
    return -1;
  }

  for (int i = 0; i < conn->numIncomingFDs; i++) {
    close(conn->incomingFDs[i]);
  }
  for (int i = 0; i < conn->numOutgoingFDs; i++) {
    close(conn->outgoingFDs[i]);
  }
  close(conn->listenSockFD);

  free(conn->incomingFDs);
  free(conn->outgoingFDs);
  memset(conn, 0, sizeof(tcp_connection));
  conn->uid = -1;  // Mark this slot as free
  return 0;
}

int tcp_listen(tcp_connection *conn) {
  return listen(conn->listenSockFD, SOMAXCONN);
}

remote_ip *accept_remote_connection(tcp_connection *conn) {
  remote_ip *ip = malloc(sizeof(remote_ip));
  ip->protocolVer = conn->options.ver;
  int newFD = -1;
  if (ip->protocolVer == AF_INET) {
    socklen_t addrlen = sizeof(ip->ipData.ipv4);
    newFD = accept(conn->listenSockFD, (struct sockaddr *)&ip->ipData.ipv4,
                   &addrlen);
  } else {
    socklen_t addrlen = sizeof(ip->ipData.ipv6);
    newFD = accept(conn->listenSockFD, (struct sockaddr *)&ip->ipData.ipv6,
                   &addrlen);
  }
  if (newFD == -1) {
    return NULL;
  }
  // Add to current connections
  conn->numIncomingFDs += 1;
  if (conn->numIncomingFDs > conn->maxIncomingFDs) {
    conn->maxIncomingFDs *= 2;
    conn->incomingFDs =
        realloc(conn->incomingFDs, sizeof(int) * conn->maxIncomingFDs);
  }
  conn->incomingFDs[conn->numIncomingFDs - 1] = newFD;
  ip->fd = newFD;
  return ip;
}

int tcp_connect_remote(tcp_connection *conn, remote_ips remotes) {
  int succeedAll = 1;
  for (int i = 0; i < remotes.len; i++) {
    int rc = -1;
    int sockfd = generate_socket(remotes.ips[i], 0, 0);
    if (remotes.ips[i].protocolVer == IPV4) {
      struct sockaddr *convert =
          (struct sockaddr *)(&(remotes.ips[i].ipData.ipv4));
      socklen_t addrlen = sizeof(*convert);
      if ((rc = connect(sockfd, convert, addrlen)) == -1) {
        succeedAll = 0;
        close(sockfd);
        continue;
      }
      // Add to current connections
      conn->numOutgoingFDs += 1;
      if (conn->numOutgoingFDs > conn->maxOutgoingFDs) {
        conn->maxOutgoingFDs *= 2;
        conn->outgoingFDs =
            realloc(conn->outgoingFDs, sizeof(int) * conn->maxOutgoingFDs);
      }
      conn->outgoingFDs[conn->numOutgoingFDs - 1] = sockfd;
      remotes.ips[i].fd = sockfd;
    } else {
      struct sockaddr *convert =
          (struct sockaddr *)(&remotes.ips[i].ipData.ipv6);
      socklen_t addrlen = sizeof(*convert);
      if ((rc = connect(sockfd, convert, addrlen)) == -1) {
        succeedAll = 0;
        close(sockfd);
        continue;
      }
      // Add to current connections
      conn->numOutgoingFDs += 1;
      if (conn->numOutgoingFDs > conn->maxOutgoingFDs) {
        conn->maxOutgoingFDs *= 2;
        conn->outgoingFDs =
            realloc(conn->outgoingFDs, sizeof(int) * conn->maxOutgoingFDs);
      }
      conn->outgoingFDs[conn->numOutgoingFDs - 1] = sockfd;
      remotes.ips[i].fd = sockfd;
    }
  }
  return succeedAll;
}

remote_ips tcp_active_accepts(tcp_connection *conn) {
  remote_ips ips;
  ips.len = conn->numIncomingFDs;
  ips.ips = malloc(sizeof(remote_ip) * ips.len);
  for (int i = 0; i < ips.len; i++) {
    remote_ip ip;
    ip.protocolVer = conn->options.ver;
    struct sockaddr addr = {0};
    socklen_t addrlen = sizeof(addr);
    getpeername(conn->incomingFDs[i], &addr, &addrlen);
    if (ip.protocolVer == IPV4) {
      ip.ipData.ipv4 = *(struct sockaddr_in *)&addr;
    } else {
      ip.ipData.ipv6 = *(struct sockaddr_in6 *)&addr;
    }
    ip.fd = conn->incomingFDs[i];
    ips.ips[i] = ip;
  }
  return ips;
}

remote_ips tcp_active_connects(tcp_connection *conn) {
  remote_ips ips;
  ips.len = conn->numOutgoingFDs;
  ips.ips = malloc(sizeof(remote_ip) * ips.len);
  for (int i = 0; i < ips.len; i++) {
    remote_ip ip;
    ip.protocolVer = conn->options.ver;
    struct sockaddr addr = {0};
    socklen_t addrlen = sizeof(addr);
    getpeername(conn->outgoingFDs[i], &addr, &addrlen);
    if (ip.protocolVer == IPV4) {
      ip.ipData.ipv4 = *(struct sockaddr_in *)&addr;
    } else {
      ip.ipData.ipv6 = *(struct sockaddr_in6 *)&addr;
    }
    ip.fd = conn->outgoingFDs[i];
    ips.ips[i] = ip;
  }
  return ips;
}

int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data,
                     size_t len) {
  int numSends = 0;
  for (int i = 0; i < remotes.len; i++) {
    int rc = send(remotes.ips[i].fd, data, len, 0);
    if (rc > 0) {
      numSends++;
    }
  }
  return numSends;
}

int receive_tcp_message(tcp_connection *conn, remote_ips ips, int senderIdx,
                        void **data, size_t *len) {
  *data = malloc(RECV_BUF_SIZE);
  if (senderIdx > ips.len - 1) {
    return -1;
  }
  remote_ip *sender = &ips.ips[senderIdx];
  return recv(sender->fd, *data, RECV_BUF_SIZE, 0);
}

int receive_tcp_message_async(tcp_connection *conn, remote_ips ips,
                              int senderIdx, void **data, size_t *len) {
  // TODO
  return 0;
}

udp_connection *create_udp_connection(conn_opt opt) {
  // TODO
  return NULL;
}

int destroy_udp_connection() {
  return 0;
  // TODO
}

remote_ips process_udp_sock_addresses(udp_connection *conn, char **ips,
                                      char **ports, int len) {
  // TODO
  remote_ips remotes = {0};
  return remotes;
}

int send_udp_message(udp_connection *conn, remote_ips remotes, void *data,
                     size_t len) {
  // TODO
  return 0;
}

remote_ip *receive_udp_message_async(udp_connection *conn, void **data,
                                     size_t *len) {
  // TODO
  return NULL;
}

remote_ip *receive_udp_message(udp_connection *conn, void **data, size_t *len) {
  // TODO
  return NULL;
}