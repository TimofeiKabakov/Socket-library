// TODO: This is just a placeholder file to figure out the API.
// Will eventually need to be rewritten.

#include "lib/net.h"
#include <stdio.h>

char *serverIP[2] = {"tux8.usask.ca"};
char *serverPort[2] = {"30553"};

int main() {
  Initialize();
  conn_opt opt = {0};
  opt.ver = IPV4;
  tcp_connection *conn = create_tcp_connection(opt);

  remote_ips servers = process_tcp_sock_addresses(conn, serverIP, serverPort, 1);

  int grub;
  grub = tcp_connect_remote(conn, servers);

  remote_ips active = tcp_active_connects(conn);

  int res = send_tcp_message(conn, active, "asdf\n", sizeof("asdf\n"));
  printf("send res: %d\n", res);

  free_sock_addresses(servers);

  while (1) {
  }

  /*
  conn_opt options = {0};
  tcp_connection *conn = create_tcp_connection(options);

  while (1) {
    remote_ips server = process_tcp_sock_addresses(conn, serverIP, serverPort, 1);
    tcp_connect_remote(conn, server);
    
    void *data;  // Some request
    size_t dataLen;
    send_tcp_message(conn, server, data, dataLen);  // Non-blocking

    // Wait for server response
    void *responseData;
    size_t responseLen;
    receive_tcp_message(conn, &responseData, &responseLen);
  }
  */
}