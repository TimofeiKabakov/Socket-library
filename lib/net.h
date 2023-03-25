#ifndef __API_H__
#define __API_H__

#include "stddef.h"
#include "stdint.h"

/** Forward declared opaque types. These are implementation-specific. */
struct tcp_connection;
typedef struct tcp_connection tcp_connection;
struct udp_connection;
typedef struct udp_connection udp_connection;
struct remote_ip;
typedef struct remote_ip remote_ip;

/** Shared types. These are common across all implementations */
enum IPVersion { IPV4, IPV6, DONT_CARE };
typedef struct conn_opt {
  enum IPVersion ver;
  size_t timeout;
  uint16_t port_num;
} conn_opt;
typedef struct remote_ips {
  remote_ip *ips;
  size_t len;
} remote_ips;

#define MAX_CONNECTION_OBJECTS 10

// TODO: Define error codes.

/**
 * @brief Initializes the library for first use.
 *
 * This function does any necessary initialization functions in order to set up
 * the library for use by the client. For example, it may initialize needed data
 * structures or allocate required memory for the library to function. This
 * function MUST be called prior to calling any other function in this library.
 *
 * @return 0 on success, or a nonzero error code if an error occured.
 */
void Initialize();
/**
 * @brief Frees a set of ip structs allocated by the library.
 * 
 * Caller should always call this method when they are done with a
 * remote_ips struct they were given by the library, in order to 
 * free its associated memory. The remote_ips struct is no longer 
 * valid upon the return of this call. A remote_ips struct from both 
 * process_tcp_sock_addresses and process_udp_sock_addresses can be 
 * freed via this method. 
 * 
 * @param ips The struct to free. 
 */
void free_sock_addresses(remote_ips ips);
/**
 * @brief Process a list of plaintext IPs for use by the library.
 *
 * IP addresses must undergo OS-specific processing in order to produce structs
 * compatible with underlying syscalls. This function can be used to translate
 * one or more IPs stored as plaintext into these OS-specific structs ahead of
 * time, avoiding multiple costly string comparisons.
 * 
 * The length of the two string arrays ips and ports must be equal to len. There 
 * must be one port for each ip, and vice versa. 
 * 
 * If any of the ip/port pairs cannot be resolved due to an underlying platform error, 
 * only the ip/port pairs that were successfully resolved will be returned.
 *
 * @param conn The connection object used for this query. 
 * @param ips An array of strings, each string representing a null-terminated IP
 * address in the traditional "dotted-decimal" format.
 * @param ports An array of strings, each string representing a null-terminated port
 * corresponding to a given IP address in ips.
 * @param len The number of elements in the ips array and the ports array. 
 * @return A struct representing an array of remote_ip structs.
 */
remote_ips process_tcp_sock_addresses(tcp_connection *conn, char **ips, char **ports, int len);
/**
 * @brief Creates a new tcp connection
 *
 * @param opt A struct of possible options that can be used to configure the
 * connection
 * @return A pointer to the newly created connection, or NULL
 * if an error occured.
 */
tcp_connection *create_tcp_connection(conn_opt opt);
/**
 * @brief Releases an existing tcp connection
 *
 * @return 0 on success, or a nonzero value if an error occured.
 */
int destroy_tcp_connection(tcp_connection *conn);
/**
 * @brief Listens for incoming connections.
 *
 * A process can use this function to mark itself as listening for a remote connection.
 * The connection will listen on the port number provided by the conn_opt struct.
 * 
 * Caller is responsible for freeing the returned remote_ip struct. 
 *
 * @param conn The connection object to listen with.
 * @return 1 is the connection is successfully listening, 0 otherwise.
 */
int tcp_listen(tcp_connection *conn);
/**
 * @brief Wait for incoming remote connections on a listen port and accept them.
 * 
 * @param conn The connection to wait with
 * @return remote_ip* The address of the remote host that just connected
 */
remote_ip *accept_remote_connection(tcp_connection *conn);
/**
 * @brief Establish a connection to a remote host.
 *
 * Caller may attempt to establish a connection with multiple remote hosts at
 * once. The remote host must be listening with a call to tcp_listen.
 *
 * @param conn The connection object to establish this connection with.
 * @param remotes A list of one or more remote connections to attempt to
 * establish
 * @return 0 if every connection was successfully opened, nonzero if at least
 * one connection failed to be established.
 */
int tcp_connect_remote(tcp_connection *conn, remote_ips remotes);
/**
 * @brief Returns a list of the currently connected remote hosts.
 *
 * Upon return of this function, caller receives a list of remote hosts that it
 * is currently connected to as a result of either accept_remote_connection or
 * tcp_connect_remote.
 *
 * @param conn The connection object to query remote hosts on.
 * @return A list of remote hosts.
 */
remote_ips *tcp_active_connections(tcp_connection *conn);
/**
 * @brief Sends a tcp data transmission to hosts represented by remotes
 *
 * @param conn The connection to use for this transmission.
 * @param remotes A list of remote IP addresses to send this transmission to.
 * Multiple IP addresses represents a multicast transmission to multiple hosts.
 * @param data A pointer to the data to send.
 * @param len The length of the data to send, in bytes.
 * @return 0 on success, or a nonzero value if an error occured
 */
int send_tcp_message(tcp_connection *conn, remote_ips remotes, void *data,
                     size_t len);
/**
 * @brief Retrieves a pending TCP message, blocking if none exists.
 *
 * @param conn The connection to use for this transmission.
 * @param data A pointer to a pointer that will hold the received message
 * @param len The length of the received message, in bytes
 * @return 0 on success, or a nonzero value if an error occured.
 */
int receive_tcp_message(tcp_connection *conn, void **data, size_t *len);
/**
 * @brief Retrieves a pending TCP message, if one exists.
 *
 * This function is the asynchronous, nonblocking version of
 * receive_tcp_message. It will immediately return, with data set to NULL, if no
 * transmission is ready to be received.
 *
 * If this function returns an error, the values of data and len are
 * implementation defined and should not be relied on.
 *
 * @param conn The connection to use for this transmission
 * @param data A pointer to a pointer that will hold the received message, or
 * NULL if there was no message
 * @param len The length of the message, in bytes, if there was a message ready
 * to be received.
 * @return 0 on success, or a nonzero value if an error occured.
 */
int receive_tcp_message_async(tcp_connection *conn, void **data, size_t *len);

/**
 * @brief Create a new udp connection.
 *
 * @param opt A struct of possible options that can be used to configure the
 * connection
 * @return A pointer to the newly created connection, or NULL
 * if an error occured.
 */
udp_connection *create_udp_connection(conn_opt opt);
/**
 * @brief Releases an existing udp connection
 *
 * @return 0 on success, or a nonzero value if an error occured.
 */
int destroy_udp_connection();
/**
 * @brief Process a list of plaintext IPs for use by the library.
 *
 * IP addresses must undergo OS-specific processing in order to produce structs
 * compatible with underlying syscalls. This function can be used to translate
 * one or more IPs stored as plaintext into these OS-specific structs ahead of
 * time, avoiding multiple costly string comparisons.
 * 
 * The length of the two string arrays ips and ports must be equal to len. There 
 * must be one port for each ip, and vice versa. 
 * 
 * If any of the ip/port pairs cannot be resolved due to an underlying platform error, 
 * only the ip/port pairs that were successfully resolved will be returned.
 *
 * @param conn The connection object used for this query. 
 * @param ips An array of strings, each string representing a null-terminated IP
 * address in the traditional "dotted-decimal" format.
 * @param ports An array of strings, each string representing a null-terminated port
 * corresponding to a given IP address in ips.
 * @param len The number of elements in the ips array and the ports array. 
 * @return A struct representing an array of remote_ip structs.
 */
remote_ips process_udp_sock_addresses(udp_connection *conn, char **ips, char **ports, int len);
/**
 * @brief Sends a udp data transmission to hosts represented by remotes
 *
 * @param conn The connection to use for this transmission.
 * @param remotes A list of remote IP addresses to send this transmission to.
 * Multiple IP addresses represents a multicast transmission to multiple hosts.
 * @param data A pointer to the data to send.
 * @param len The length of the data to send, in bytes.
 * @return 0 on success, or a nonzero value if an error occured
 */
int send_udp_message(udp_connection *conn, remote_ips remotes, void *data,
                     size_t len);
/**
 * @brief Retrieves a pending UDP message, blocking if none exists.
 *
 * @param conn The connection to use for this transmission.
 * @param data A pointer to a pointer that will hold the received message
 * @param len The length of the received message, in bytes
 * @return 0 on success, or a nonzero value if an error occured.
 */
remote_ip *receive_udp_message(udp_connection *conn, void **data, size_t *len);
/**
 * @brief Retrieves a pending UDP message, if one exists.
 *
 * This function is the asynchronous, nonblocking version of
 * receive_udp_message. It will immediately return, with data set to NULL, if no
 * transmission is ready to be received.
 *
 * If this function returns an error, the values of data and len are
 * implementation defined and should not be relied on.
 *
 * @param conn The connection to use for this transmission
 * @param data A pointer to a pointer that will hold the received message, or
 * NULL if there was no message
 * @param len The length of the message, in bytes, if there was a message ready
 * to be received.
 * @return 0 on success, or a nonzero value if an error occured.
 */
remote_ip *receive_udp_message_async(udp_connection *conn, void **data,
                                     size_t *len);
#endif