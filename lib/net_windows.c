#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "net.h"

#pragma comment(lib, "ws2_32.lib")

typedef struct tcp_connection {
  int listenSockFD;
  int *incomingFDs;
  size_t numIncomingFDs;
  size_t maxIncomingFDs;
  int *outgoingFDs; 
  size_t numOutgoingFDs;
  size_t maxOutgoingFDs;
  conn_opt options;
  int uid;
  int protocolVerPlatSpecific;
} tcp_connection;

/* contains information about the Windows Sockets implementation */
WSADATA wsaData; 

tcp_connection activeConnections[MAX_CONNECTION_OBJECTS];
size_t connObjects = 0;
int nextUID = 0;

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
  } else {
    for (int i = 0; i < MAX_CONNECTION_OBJECTS; i++) {
      activeConnections[i].uid = -1;
      activeConnections[i].listenSockFD = -1;
      activeConnections[i].numIncomingFDs = 0;
      activeConnections[i].numOutgoingFDs = 0;
    }
  }
}

void free_sock_addresses(remote_ips ips) {
  free(ips.ips);
}

remote_ips process_tcp_sock_addresses(tcp_connection *conn, const char **ips, const char **ports, int len) {
  remote_ips ipList = {0};
  ipList.ips = malloc(sizeof(remote_ip) * len);

  int rc = -1;
  for (int i = 0; i < len; i++) {
    struct addrinfo *res = NULL, hints;

    // TODO: ZeroMemory() wraps memset(), need to figure out which one is better
    // microsoft documentation uses ZeroMemory()
    ZeroMemory(&hints, sizeof hints);
    
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

    // tell getaddrinfo() what it should look for
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if ((rc = getaddrinfo(ips[i], ports[i], &hints, &res)) == 0) {
      struct addrinfo *candidate = NULL;
      // TODO: research on whether this loop is neccessary, because now it's 
      // logically inexistent, maybe we can use it to check other stuff, maybe 
      // we need to remove it
      for (candidate = res; candidate != NULL; candidate = candidate->ai_next) {
        remote_ip ip = {0};

        if (candidate->ai_family == AF_INET) {
          ip.protocolVer = AF_INET;
          memcpy(&ip.ipData.ipv4, (struct sockaddr_in*)candidate->ai_addr, sizeof(struct sockaddr_in));
        } else {
          ip.protocolVer = AF_INET6;
          memcpy(&ip.ipData.ipv6, (struct sockaddr_in6*)candidate->ai_addr, sizeof(struct sockaddr_in6));
        }

        ipList.ips[ipList.len] = ip;
        ipList.len++;
        break;
      }
      freeaddrinfo(res);
      // TODO: should WSAClenup() be put here?
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
      if (opt.ver == DONT_CARE) {
        activeConnections[i].options.ver = IPV4;
      }
      activeConnections[i].incomingFDs = malloc(sizeof(int) * 10);
      activeConnections[i].outgoingFDs = malloc(sizeof(int) * 10);
      activeConnections[i].maxIncomingFDs = 10;
      activeConnections[i].maxOutgoingFDs = 10;

      /* initiate socket file descriptor */
      int iCandidate, iResult;
      struct addrinfo *result = NULL, hints;

      ZeroMemory(&hints, sizeof(hints));
      hints.ai_family = activeConnections[i].options.ver;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_flags = AI_PASSIVE;
     
      /* convert provided port num to string for further method calls */
      char portNumStr[6];
      sprintf(portNumStr, "%d", opt.port_num);

      /* get info for a particular port number provided in the opt parameter */
      iResult = getaddrinfo(NULL, portNumStr, &hints, &result);
      if (iResult != 0) {
          printf("getaddrinfo failed: %d\n", iResult);
          return NULL;
      }

      /* generate a local listening socket and bind it */
      SOCKET ListenSocket = INVALID_SOCKET;
      struct addrinfo *candidate = NULL;

      for (candidate = result; candidate != NULL; candidate = candidate->ai_next) {
        
        ListenSocket = socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);

        if (ListenSocket == INVALID_SOCKET) {
          printf("Error at socket(): %d\n", WSAGetLastError());
          continue;
        }

        /* bind the listening socket */
        iCandidate = bind(ListenSocket, candidate->ai_addr, (int) candidate->ai_addrlen);

        if (iCandidate == SOCKET_ERROR) {
            printf("bind failed with error: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            continue;
        }
        
        break;
      }

      freeaddrinfo(result);

      if(candidate == NULL || iCandidate == SOCKET_ERROR || ListenSocket == INVALID_SOCKET) {
        printf("Failed to bind socket\n");
        return NULL;
      }

      activeConnections[i].listenSockFD = ListenSocket;

      if (activeConnections[i].listenSockFD == -1) {
        printf("Error generating a socket for this connection\n");
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
    closesocket(conn->incomingFDs[i]);
  }
  for (int i = 0; i < conn->numOutgoingFDs; i++) {
    closesocket(conn->outgoingFDs[i]);
  }
  closesocket(conn->listenSockFD);

  free(conn->incomingFDs);
  free(conn->outgoingFDs);
  memset(conn, 0, sizeof(tcp_connection));
  conn->uid = -1;  // Mark this slot as free
  return 0;
}

int tcp_listen(tcp_connection *conn) {
  int listenReturn = listen(conn->listenSockFD, SOMAXCONN);

  if (listenReturn == SOCKET_ERROR) {
    printf( "Listen failed with error: %d\n", WSAGetLastError() );
    closesocket(conn->listenSockFD);
    WSACleanup();
    return 1;
  }

  return listenReturn;
}

int tcp_connect_remote(tcp_connection *conn, remote_ips remotes) {
  int succeedAll = 1;
  /* Iterate over the remote_ips struct and establish connection with every ip inside of it */
  for(int i = 0; i < remotes.len; i++) {
    int sockaddr_length;
    struct sockaddr *sockaddr_to_connect;

    /*
      Extract the ip address of the required version from the remote_ip union
      and cast it to the sockaddr pointer. 
    */
    if (remotes.ips[i].handle->protocolVer == AF_INET) {
      sockaddr_to_connect = (struct sockaddr*) &remotes.ips[i].handle->ipData.ipv4;
      sockaddr_length = sizeof(struct sockaddr_in);
    } else {
      sockaddr_to_connect = (struct sockaddr*) &remotes.ips[i].handle->ipData.ipv6;
      sockaddr_length = sizeof(struct sockaddr_in6);
    }

    /* initiate socket file descriptor */
    int iResult = -1;
    struct addrinfo *result = NULL, hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = remotes.ips[i].handle->protocolVer;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* IS IT RIGHT HERE????? */

    /* get info for a particular port number provided in the opt parameter */
    iResult = getaddrinfo(remotes.ips[i].addr, remotes.ips[i].port, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 0;
    }

    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *candidate = NULL;

    for (candidate = result; candidate != NULL; candidate = candidate->ai_next) {

      ConnectSocket = socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol); 

      if (ConnectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %d\n", WSAGetLastError());
        continue;
      }

      if (connect(ConnectSocket, sockaddr_to_connect, sockaddr_length) == SOCKET_ERROR) {
        closesocket(ConnectSocket);  
        ConnectSocket = INVALID_SOCKET;
        continue;
      }

      break;
    }

    freeaddrinfo(result);

    if (candidate == NULL || ConnectSocket == INVALID_SOCKET) {
      succeedAll = 0;
      printf("failed to connect: %d\n", WSAGetLastError());
      WSACleanup();
      continue;
    }
    
    /* If got here, it means we connected, we need to add the connection to outgoingFDs */
    conn->numOutgoingFDs += 1;
    if (conn->numOutgoingFDs > conn->maxOutgoingFDs) {
      conn->maxOutgoingFDs *= 2;
      conn->outgoingFDs = realloc(conn->outgoingFDs, sizeof(int) * conn->maxOutgoingFDs);
    }
    conn->outgoingFDs[conn->numOutgoingFDs - 1] = ConnectSocket;
    remotes.ips[i].handle->fd = ConnectSocket;
  }

  return succeedAll;
}

// remote_ips *tcp_active_connections(tcp_connection *conn) {
//   // TODO
// }

// int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data,
//                      size_t len) {
//   // TODO
// }

// int receive_tcp_message_async(tcp_connection *conn, remote_ips ips, int senderIdx, void **data, size_t *len) {
//   // TODO
// }

// int receive_tcp_message(tcp_connection *conn, remote_ips ips, int senderIdx, void **data, size_t *len) {
//   // TODO
// }

// udp_connection *create_udp_connection(conn_opt opt) {
//   // TODO
// }

// int destroy_udp_connection() {
//   // TODO
// }

// remote_ips process_udp_sock_addresses(udp_connection *conn, char **ips, char **ports, int len) {
//   // TODO
// }

// int send_udp_message(udp_connection *conn, remote_ips remotes, void *data,
//                      size_t len) {
//   // TODO
// }

// remote_ip *receive_udp_message_async(udp_connection *conn, void **data,
//                                      size_t *len) {
//   // TODO
// }

// remote_ip *receive_udp_message(udp_connection *conn, void **data, size_t *len) {
//   // TODO
// }

// remote_ips tcp_active_connects(tcp_connection *conn) {
//   // TODO
// }

// remote_ips tcp_active_accepts(tcp_connection *conn) {
//   // TODO
// }

// remote_ip *accept_remote_connection(tcp_connection *conn) {
//   // TODO
// }