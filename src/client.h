#ifndef _client_h
#define _client_h

int tcp_connect(char *host,int port);
int connect_SSL(SSL *ssl, SSL_CTX *ctx, int sock);
void close_SSL(SSL *ssl, int sock);
void send_data(SSL *ssl, char* command);
void rec_data(SSL *ssl,char** response);

#endif

