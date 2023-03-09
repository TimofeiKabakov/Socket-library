#include "lib/net.h"

int main() {
    conn_opt options = {0};
    tcp_connection *conn = create_tcp_connection(options);
}