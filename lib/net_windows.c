#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "net.h"

#pragma comment(lib, "ws2_32.lib")

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

typedef struct remote_ip {
  int protocolVer;
  union {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
  } ipData;
} remote_ip;

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
    struct addrinfo *res = NULL, *ptr = NULL, hints;

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

int tcp_listen(tcp_connection *conn) {
  // TODO
}

int tcp_connect_remote(tcp_connection *conn, remote_ips remotes) {

  /* Iterate over the remote_ips struct and establish connection with every ip inside of it */
  for(int i = 0; i < remotes.len; i++) {
    SOCKET ConnectSocket = INVALID_SOCKET;

    socklen_t sockaddr_length;
    struct sockaddr *sockaddr_to_connect;

    /* 
      The address family specification argument in socket() call is defined depending on the 
      version of the IP indicated in `tcp_connection *conn` parameter 
    */
    ConnectSocket = socket(conn->options.ver, SOCK_STREAM, IPPROTO_TCP);

    /* Check for errors after calling socket() */
    if (ConnectSocket == INVALID_SOCKET) {
      printf("Error at socket(): %ld\n", WSAGetLastError());
      WSACleanup();
      return 1;
    }

    /*
      Extract the ip address of the required version from the remote_ip union
      and cast it to the sockaddr pointer. 
    */
    if (conn->options.ver == AF_INET) {
      sockaddr_to_connect = (struct sockaddr*) &remotes.ips[i].ipData.ipv4;
      sockaddr_length = sizeof(struct sockaddr_in);
    } else {
      sockaddr_to_connect = (struct sockaddr*) &remotes.ips[i].ipData.ipv6;
      sockaddr_length = sizeof(struct sockaddr_in6);
    }

    int iResult = -1;
    /* Establish the connection */
    iResult = connect(ConnectSocket, sockaddr_to_connect, sockaddr_length);

    /* Check for errors after calling connect() */
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);  
        ConnectSocket = INVALID_SOCKET;
    }

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect!\n");
        WSACleanup();
        return 1;
    }
  }

  return 0;
}

remote_ips *tcp_active_connections(tcp_connection *conn) {
  // TODO
}

int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data,
                     size_t len) {
  // TODO
}

int receive_tcp_message_async(tcp_connection *conn, remote_ips ips, int senderIdx, void **data, size_t *len) {
  // TODO
}

int receive_tcp_message(tcp_connection *conn, remote_ips ips, int senderIdx, void **data, size_t *len) {
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

remote_ips tcp_active_connects(tcp_connection *conn) {
  // TODO
}

remote_ips tcp_active_accepts(tcp_connection *conn) {
  // TODO
}

remote_ip *accept_remote_connection(tcp_connection *conn) {
  // TODO
}