// TODO: This is just a placeholder file to figure out the API.
// Will eventually need to be rewritten.

#include "lib/net.h"
#include <stdio.h>

int main() {
  Initialize();
  conn_opt options = {0};
  options.ver = IPV4;
  options.port_num = 30553;
  tcp_connection *conn = create_tcp_connection(options);
  if (conn == NULL) {
    printf("Fatal error!\n");
  }

  while (1) {
    tcp_listen(conn);
    void *data = NULL;
    size_t msgLen = 0;

    // Blocking, would want to move to dedicated thread
    printf("Try connect...\n");
    remote_ip *client = accept_remote_connection(conn);
    printf("Connected\n");

    remote_ips active = tcp_active_accepts(conn);
    

    for(int i = 0; i < active.len; i++) {
      void *resultData;
      size_t resultLen;
      receive_tcp_message(conn, active, i, &resultData, &resultLen);
      printf("%s\n", (char*)resultData);
    }
  }
}