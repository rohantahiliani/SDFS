#ifndef _server_h
#define _server_h

#define DHFILE "dh1024.pem"

char* CERTFILE;
char* KEYFILE;
char* PUBFILE;
char* PASSWORD;
char* OLDKEY;
char* OLDPASS;

int tcp_listen(void);
void load_dh_params(SSL_CTX *ctx,char *file);
void generate_eph_rsa_key(SSL_CTX *ctx);

void close_SSL(SSL *ssl, int s);
int rec_data(char* command, SSL *ssl);
int send_data(SSL *ssl, char* output);

int getSHA1(char* data, char** result);
int encryptFile(char* response, char* hash_result, char** encrypt_result);
int decryptFile(char* response, unsigned char* hash_result, char** decrypt_result, int data_len);
int RSACrypt(unsigned char* data, int mode, char* key, char* keypass, unsigned char** result);
int recrypt();

int verify_meta(int argc, char** argv, long* time_left);
int write_meta(char* file_name, char* user, char* permission, char* key, char* data_len, int append);

int get_file(SSL *ssl, char* buf, char* owner);
int put_file(SSL *ssl, char* buf, char* owner);
int delegate(SSL *ssl, char* buf, char* owner);

#endif

