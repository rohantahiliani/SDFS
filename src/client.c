#include "common.h"

int tcp_connect(char* host, int port)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
    if(!(hp=gethostbyname(host)))
      berr_exit("Couldn't resolve host");
    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*)
      hp->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    if((sock=socket(AF_INET,SOCK_STREAM,
      IPPROTO_TCP))<0)
      err_exit("Couldn't create socket");
    if(connect(sock,(struct sockaddr *)&addr,
      sizeof(addr))<0)
      err_exit("Couldn't connect socket");
    
    return sock;
}

int connect_SSL(SSL *ssl, SSL_CTX *ctx, int sock)
{
	BIO *sbio;
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);

    if(SSL_connect(ssl)<=0) berr_exit("SSL connect error");
    char* peer_CN = (char*) calloc(1, 256);
	int verify = check_cert(ssl, ctx, &peer_CN);
	return verify;
}

void close_SSL(SSL *ssl, int sock)
{
    int r=SSL_shutdown(ssl);
    if(!r){
      shutdown(sock,1);
      r=SSL_shutdown(ssl);
    }
    switch(r){
      case 1:
        break; /* Success */
    }
    SSL_free(ssl);
	close(sock);
}


void send_data(SSL *ssl, char* command)
{
    int r;
    int request_len;
	strcat(command, "\r\n");
    request_len=strlen(command);
    r=SSL_write(ssl,command,request_len);
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
    }
}

void rec_data(SSL *ssl, char** ret_array)
{
    int r;
	char* response = ret_array[0];
	char* buf = 0;
    while(1){
	    buf = (char*)calloc(1,51);
		r=SSL_read(ssl,buf,50);
		switch(SSL_get_error(ssl,r)){
		case SSL_ERROR_NONE:
			if(response==0) response = (char*)calloc(1,52);
			else {
				char* temp = (char*)calloc(1,strlen(response)+1);
				strcat(temp, response);
				free(response);
				response = (char*)calloc(1,strlen(temp)+52);
				strcat(response, temp);
				free(temp);
			}
			strcat(response, buf);
  			break;
		default:
			berr_exit("SSL read problem");
		}
		if(SSL_pending(ssl)<=0) break;
	}
	*ret_array = (char*) calloc(1, strlen(response)+1);
	strcpy(*ret_array, response);
	free(buf);
	free(response);
}
