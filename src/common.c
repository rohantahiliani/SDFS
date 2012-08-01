#include "common.h"
#include <openssl/err.h>


BIO *bio_err=0;
static char *pass;
static int password_cb(char *buf,int num, int rwflag,void *userdata);
static void sigpipe_handle(int x);

int err_exit(string)
  char *string;
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

int berr_exit(string)
  char *string;
  {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

static int password_cb(char *buf, int num, int rwflag, void *userdata)
{
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
}

static void sigpipe_handle(int x){
}

SSL_CTX *initialize_ctx(char* certfile, char* keyfile, char* password)
{    
	SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      SSL_library_init();
      SSL_load_error_strings();
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    signal(SIGPIPE,sigpipe_handle);
    
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    if(!(SSL_CTX_use_certificate_chain_file(ctx,certfile)))
      berr_exit("Can't read certificate file");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx,password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    if(!(SSL_CTX_load_verify_locations(ctx,CA_LIST,0)))
      berr_exit("Can't read CA list");

    return ctx;
}
     
void destroy_ctx(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}


int starts_with(char* string, char* sub)
{
	int len = strlen(sub);
	int i=0;
	for(;i<len;i++)
	if(string[i] != sub[i]) return 0;
	return 1;
}

int check_cert(SSL *ssl, SSL_CTX *ctx, char** owner)
{
    X509 *peer;
    char *peer_CN = (char*) calloc(1,256);
    
    if(SSL_get_verify_result(ssl)!=X509_V_OK){
	    printf("Certificate doesn't verify");
		return 0;
	}

    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
	strcpy(*owner, peer_CN);
	return verify_CRL(peer_CN, ctx);
}

int verify_CRL(char* owner, SSL_CTX *ctx)
{
	struct stat fsize;
	stat(CRLFILE, &fsize);
	char* line = (char*) calloc(1, fsize.st_size);
	FILE* file = fopen(CRLFILE, "r");
	int verify = 0;
	while(fgets(line, fsize.st_size, file)) {
		char status;
		char* crap_val = (char*) calloc(1,256);
		int serial;
		char unknown[8];
		char* info = (char*) calloc(1, 512);
		char* crap_val2 = (char*) calloc(1, 256);

		if(line[0]=='V') {
			sscanf(line, "%c %s %d %s %s", &status, crap_val, &serial, unknown, info);
			verify = 1;
		}
		else {
			sscanf(line, "%c %s %s %d %s %s", &status, crap_val, crap_val2, &serial, unknown, info); 
			verify = 0;
		}
		int len = strlen(owner),i;
		for(i=0; i<len; i++) if(owner[len - i -1] != info[strlen(info) - i -1]) break;
		free(crap_val);
		free(crap_val2);
		free(info);
		if(i==len) break;
	}
	printf("CRL Verification Status for %s: %d\n", owner, verify);
	fclose(file);
	return verify;
}
