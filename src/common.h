#ifndef _common_h
#define _common_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#define CA_LIST "../CA/CondorSigningCA1/signing-ca-1.crt"
#define CRLFILE "../CA/CondorSigningCA1/ca.db.index"

#define HOST	"localhost"
#define RANDOM  "random.pem"
#define PORT	4433
#define BUFSIZZ 1024

extern BIO *bio_err;
int berr_exit (char *string);
int err_exit(char *string);
int starts_with(char*, char*);

SSL_CTX *initialize_ctx(char* certfile, char *keyfile, char *password);
int check_cert(SSL *ssl, SSL_CTX *ctx, char** owner);
int verify_CRL(char* owner, SSL_CTX *ctx);
void destroy_ctx(SSL_CTX *ctx);

#ifndef ALLOW_OLD_VERSIONS
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
#error "Must use OpenSSL 0.9.6 or later"
#endif
#endif

#endif


