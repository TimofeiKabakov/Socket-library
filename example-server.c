// TODO: This is just a placeholder file to figure out the API.
// Will eventually need to be rewritten.

#include "lib/net.h"

int main() {
  conn_opt options = {0};
  tcp_connection *conn = create_tcp_connection(options);

  while (1) {
    // Blocking, would want to move to dedicated thread
    remote_ip *client = tcp_listen(conn);

    void *data = NULL;
    size_t msgLen = 0;
    receive_tcp_message(conn, &data, &msgLen);  // Blocking

    // Process request with child threads
    // ...
    void *resultData;
    int resultLen;

    // Non-blocking broadcast to all active connections
    remote_ips *remotes = tcp_active_connections(conn);
    send_tcp_message(conn, *remotes, resultData, resultLen);
  }
}