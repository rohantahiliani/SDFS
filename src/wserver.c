#include "common.h"
#include "server.h"

int main(int argc, char** argv)
{
	if(argc<4) {
		printf("Usage: ./wserver cert-file priv-key-file pub-key-file.\n");
		exit(0);
	}
	else {
		CERTFILE = argv[1];
		KEYFILE = argv[2];
		PUBFILE = argv[3];
		const char* PROMPT = "Enter password for Old Key file: ";
		if(argc == 5) {
			OLDKEY = argv[4];
			PASSWORD = getpass(PROMPT);
			OLDPASS = (char*) calloc(1, strlen(PASSWORD)+1);
			strcpy(OLDPASS, PASSWORD);
		}
		PROMPT = "Enter password for Key file: ";
		PASSWORD = getpass(PROMPT);
	}

    int sock,s;
    BIO *sbio;
    SSL_CTX *ctx;
    SSL *ssl;
    int r;
    pid_t pid;
    char buf[BUFSIZZ];
	char *owner = (char*) calloc(1,256);

    ctx=initialize_ctx(CERTFILE,KEYFILE,PASSWORD);
    load_dh_params(ctx,DHFILE);    

    sock=tcp_listen();
	if((s=accept(sock,0,0))<0) err_exit("Problem accepting");
	sbio=BIO_new_socket(s,BIO_NOCLOSE);
	ssl=SSL_new(ctx);
	SSL_set_bio(ssl,sbio,sbio);
	SSL_set_verify(ssl,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);        
	if((r=SSL_accept(ssl)<=0)) berr_exit("SSL accept error");
	if(check_cert(ssl, ctx, &owner)<=0) {
		send_data(ssl, "Revoked");
		printf("Connection Closed.\n");
		close_SSL(ssl, sock);
		destroy_ctx(ctx);
		exit(0);
	}
	send_data(ssl, "Approved");
	printf("User connected: %s\n", owner);

	if((pid=fork())){
		close(s);
	}
	else {
		if(argc == 5) {recrypt();}
		while(1){
			memset((void*)buf, 0, BUFSIZZ);
			if(rec_data(buf, ssl)>0)
			{
				printf("Command received: %s\n", buf);
				if(starts_with(buf, "PUT")){
					put_file(ssl, buf, owner);
				}
				else if(starts_with(buf, "GET")){
					get_file(ssl, buf, owner);
				}
				else if(starts_with(buf, "DELEGATE")){
					delegate(ssl, buf, owner);
				}
				else if(starts_with(buf, "END")){
					close_SSL(ssl, sock);
					break;
				}
				else {
					printf("Command not recognized\n");
				}
			}
			else{
				perror("Error receiving command\n");
				break;
			}
		}
	}
    destroy_ctx(ctx);
    exit(0);
  }
