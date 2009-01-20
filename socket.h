
int socket_join_multicast(int sock, char *addr);
int socket_set_ttl(int sock, int ttl);
int socket_set_nonblock(int sock);
int socket_open(char *laddr, int port, int proto);
void socket_close(int sock);
int socket_connect(int sock, char *addr, uint32_t saddr, int port);
int socket_listen(int sock, int backlog);
