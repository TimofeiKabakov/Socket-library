// TODO: This is just a placeholder file to figure out the API.
// Will eventually need to be rewritten.

#include "lib/net.h"

char *serverIP[1] = {""};
char *serverPort[1] = {""};

int main() {
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
}