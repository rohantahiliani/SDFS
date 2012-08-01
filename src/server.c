#include "common.h"
#include "server.h"

int tcp_listen()
{
    int sock;
    struct sockaddr_in sin;
    int val=1;
    
    if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
      err_exit("Couldn't make socket");
    
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr=INADDR_ANY;
    sin.sin_family=AF_INET;
    sin.sin_port=htons(PORT);
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,
      &val,sizeof(val));
    
    if(bind(sock,(struct sockaddr *)&sin,
      sizeof(sin))<0)
      berr_exit("Couldn't bind");
    listen(sock,5);  

    return(sock);
}

void load_dh_params(SSL_CTX *ctx,char* file)
{
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL)
      berr_exit("Couldn't open DH file");

    ret=PEM_read_bio_DHparams(bio,NULL,NULL,
      NULL);
    BIO_free(bio);
    if(SSL_CTX_set_tmp_dh(ctx,ret)<0)
      berr_exit("Couldn't set DH parameters");
}

void generate_eph_rsa_key(SSL_CTX *ctx)
{
    RSA *rsa;

    rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);
    
    if (!SSL_CTX_set_tmp_rsa(ctx,rsa))
      berr_exit("Couldn't set RSA key");

    RSA_free(rsa);
}
  

// My functions

int getSHA1(char* data, char** result)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md = EVP_sha1();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;
	OpenSSL_add_all_digests();
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, strlen(data));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	
	*result = (char*) calloc(1, md_len*2+1);
	for(i = 0; i < md_len; i++) {
		char hex_print[2];
		sprintf(hex_print, "%02x", md_value[i]);
		strcat(*result, hex_print);
	}
	return 1;
}

int encryptFile(char* response, char* hash_result, char** encrypt_result)
{
	EVP_CIPHER_CTX encrypt_ctx;
	unsigned char key[32], iv[32];
	int i;
	for(i=0;i<32;i++) key[i] = hash_result[i];
	for(i=0;i<32;i++) iv[i] = hash_result[8+i];
	int len = strlen(response)+1;
	int clen = len+AES_BLOCK_SIZE;
	int flen;
	*encrypt_result = (char*) calloc(1, clen);
	EVP_CIPHER_CTX_init(&encrypt_ctx);
	EVP_EncryptInit_ex(&encrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(&encrypt_ctx, (unsigned char*)*encrypt_result, &clen, (unsigned char*)response, len);
	EVP_EncryptFinal_ex(&encrypt_ctx, ((unsigned char*)*encrypt_result)+clen, &flen);
	return clen+flen;
}

int decryptFile(char* response, unsigned char* hash_result, char** decrypt_result, int data_len)
{
	EVP_CIPHER_CTX decrypt_ctx;
	unsigned char key[32], iv[32];
	int i;
	for(i=0;i<32;i++) key[i] = hash_result[i];
	for(i=0;i<32;i++) iv[i] = hash_result[8+i];
	int len = data_len;
	int olen = data_len+2;
	int flen;
	*decrypt_result = (char*) calloc(1, olen);
	EVP_CIPHER_CTX_init(&decrypt_ctx);
	EVP_DecryptInit_ex(&decrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(&decrypt_ctx, (unsigned char*)*decrypt_result, &olen, (unsigned char*)response, len);
	EVP_DecryptFinal_ex(&decrypt_ctx, (unsigned char*)*decrypt_result+olen, &flen);
	return 1;
}

int RSACrypt(unsigned char* data, int mode, char* key, char* keypass, unsigned char** result)
{
	FILE *file;
	struct stat fsize;
	RSA *rsa;

	if(mode){
		stat(PUBFILE, &fsize);
		file = fopen(key, "r");
		if(file!=NULL){
			char* pkey = (char*) calloc(1,fsize.st_size+1);
			fread(pkey, fsize.st_size, 1, file);
			fclose(file);

			BIO *bp = BIO_new_mem_buf(pkey, -1);
			rsa = PEM_read_bio_RSA_PUBKEY(bp, 0, 0, 0);
			BIO_free(bp);

			*result = (unsigned char*)calloc(1,RSA_size(rsa)+1);
			RSA_public_encrypt(strlen((char*)data), data, *result, rsa, RSA_PKCS1_PADDING);
		}
		else printf("Couldn't open public key.\n");
	}
	else{
		file = fopen(key, "r");
		if(file!=NULL){
			rsa = PEM_read_RSAPrivateKey(file, 0, 0, keypass);
			fclose(file);

			*result = (unsigned char*)calloc(1,RSA_size(rsa)+1);
			RSA_private_decrypt(RSA_size(rsa), data, *result, rsa, RSA_PKCS1_PADDING);
		}
		else printf("Couldn't open private key.\n");
	}
	int ret_val = RSA_size(rsa);
	RSA_free(rsa);

	return ret_val;
}

int recrypt()
{
	printf("Recrypting.\n");
	DIR *dir;
	struct dirent *ent;
	dir = opendir ("../FileSystem/metadata/");
	if (dir != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if(!strcmp(ent->d_name, "..") || !strcmp(ent->d_name, ".")) continue;
			char* path = (char*) calloc(1, 50+strlen(ent->d_name));
			strcat(path, "../FileSystem/metadata/");
			strcat(path,ent->d_name);
			FILE* file = fopen(path, "r");
			struct stat fsize;
			stat(path, &fsize);
			char* data = (char*) calloc(1, fsize.st_size+1);
			fread(data, fsize.st_size, 1, file);
			fclose(file);
			char* key = (char*) calloc(1,260);
			sscanf(data, "%s", key);
			data = &data[strlen(key)];

			unsigned char* result_key = (unsigned char*)calloc(1, 130);
			int i;
			for(i=0; i<strlen(key); i+=2) {
				unsigned int hex_print;
				sscanf(&key[i], "%2x", &hex_print);
				result_key[i/2] = hex_print;
			}

			unsigned char* sha_key = 0;
			RSACrypt(result_key, 0, OLDKEY, OLDPASS, &sha_key);
			unsigned char* rsa_key = 0;
			int len = RSACrypt(sha_key, 1, PUBFILE, 0, &rsa_key);
			free(result_key);
			result_key = (unsigned char*) calloc(1, 260);
			for(i=0; i<len ; i++) {
				char hex_print[2];
				sprintf(hex_print, "%02x", rsa_key[i]);
				strcat((char*)result_key, hex_print);
			}
			file=fopen(path,"w");
			fwrite(result_key, strlen((char*)result_key), 1, file);
			fwrite(data, strlen(data), 1, file);

			fclose(file);
			free(result_key);
			free(sha_key);
			free(key);
			free(path);
	  	}
		closedir (dir);
		return 1;
	} else return 0;
}

int verify_meta(int argc, char** argv, long* time_left)
{
	char* subject = 0;
	int permission = 0, is_owner = 0;
	long time_allowed;

	char* file_name = argv[0];
	char* accessor = argv[1];
	char* key = (char*) calloc(1,260);
	char* data_len = (char*) calloc(1,20);
	char* path = (char*) calloc(1, 50+strlen(file_name));
	strcat(path, "../FileSystem/metadata/.");
	strcat(path,file_name);
	FILE *file = fopen(path, "r");

	if(!file) {
		permission = 2;
	}
	else {
		fclose(file);
		file = fopen(path,"r");
		char* data = (char*) calloc(1, 512);
		fgets(key, 260, file);
		fgets(data_len, 20, file);
		if(argc>2) {
			strncat(argv[2], key, strlen(key)-1);
			strncat(argv[3], data_len, strlen(data_len)-1);
		}
		while((data = fgets(data, 500, file)) != NULL) {
			int perm_read;
			subject = (char*) calloc(1, 500);
			sscanf(data, "%s %d %d %ld", subject, &perm_read, &is_owner, &time_allowed);
			if(!strcmp(accessor, subject)) {
				if(is_owner) {
					permission = perm_read;
					break;
				}
				else {
					if(time_allowed > time(0)) {
						permission = perm_read;
						if(time_left!=0) *time_left = time_allowed;
						break;
					}
					else {
						permission = 0;
					}
				}
			}
			free(data);
			free(subject);
			data = (char*) calloc(1, 512);
		}
		fclose(file);
	}
	free(key);
	free(data_len);
	free(path);
	return permission;
}

int write_meta(char* file_name, char* user, char* permission, char* key, char* data_len, int append)
{
	char* path = (char*) calloc(1, 50+strlen(file_name));
	strcat(path, "../FileSystem/metadata/.");
	strcat(path, file_name);
	FILE *file = fopen(path, "r");
	if(!file || append) {
		if(file!=NULL) {
			fclose(file);
		}
		file = fopen(path, "a");
		if(!append) {
			fwrite(key, strlen(key), 1, file);
			fwrite("\n", 1, 1, file);
			fwrite(data_len, strlen(data_len), 1, file);
			fwrite("\n", 1, 1, file);
		}
		fwrite(user, strlen(user), 1, file);
		fwrite(permission, strlen(permission), 1, file);
		fclose(file);
		file = 0;
	}
	if(file!=NULL) fclose(file);
	free(path);
	return 1;
}

int delegate(SSL *ssl, char* buf, char* owner)
{
	char* file_name = (char*) calloc(1, 512);
	char* user = (char*) calloc(1, 512);
	long time_allowed;
	int is_dstar = 8;

	if(buf[8]=='*') is_dstar = 9;
	if(sscanf(&buf[is_dstar], "%s %s %ld", file_name, user, &time_allowed) == 3){
		char* argv[2];
		int user_perm = 0;
		long time_left;
		argv[0]=file_name;
		argv[1]=owner;
		if((user_perm = verify_meta(2, argv, &time_left))>=4) {
			if(user_perm == 6 && is_dstar == 9) {
				if(time_left <= time_allowed+time(0)) send_data(ssl, "Error: Permission Denied.\n");
			}
			char* permission = (char*) calloc(1, 100);
			char* time_str = (char*) calloc(1, 100);
			if(is_dstar == 9) strcat(permission, " 6 0 ");
			else strcat(permission, " 3 0 ");
			sprintf(time_str, "%ld", (time(0)+time_allowed));
			strcat(permission, time_str);
			strcat(permission, "\n");
			write_meta(file_name, user, permission, NULL, NULL, 1);
			send_data(ssl, "Delegate Successful.\n");
			free(file_name);
			free(user);
			free(permission);
			free(time_str);
			return 1;
		}
		else {
			send_data(ssl, "Error: Permission Denied.\n");
		}
	}
	free(file_name);
	free(user);
	return 0;
}

int get_file(SSL *ssl, char* buf, char* owner)
{
	char* output;
	char* file_name = (char*) calloc(1, strlen(&buf[4]));
	char* key = (char*) calloc(1,260);
	char* data_len = (char*) calloc(1,20);
	strncat(file_name, &buf[4], strlen(&buf[4])-1);

	char* argv[4];
	argv[0]=file_name;
	argv[1]=owner;
	argv[2]=key;
	argv[3]=data_len;

	if(verify_meta(4, argv, 0)<1){
		output = "Error: Permission denied.\n";
		send_data(ssl, output);
	}
	else{
		char* path = (char*) calloc(1, 50+strlen(file_name));
		strcat(path, "../FileSystem/files/");
		strncat(path, file_name, strlen(file_name));
		FILE *file = fopen(path, "r");
		if(file==NULL) {
			output = "Error: File does not exist.\n";
			send_data(ssl, output);
		}
		else{
			output = (char*) calloc(1, atoi(data_len));
			fread(output, atoi(data_len), 1, file);
			fclose(file);

			unsigned char* result_key = (unsigned char*)calloc(1, 130);
			int i;
			for(i=0; i<strlen(key); i+=2) {
				unsigned int hex_print;
				sscanf(&key[i], "%2x", &hex_print);
				result_key[i/2] = hex_print;
			}
			unsigned char* ukey = 0;
			RSACrypt(result_key, 0, KEYFILE, PASSWORD, &ukey);

			char* decrypt_result = 0;
			decryptFile(output, ukey, &decrypt_result, atoi(data_len));
			send_data(ssl, decrypt_result);
			free(ukey);
			free(result_key);
			free(decrypt_result);
			free(output);
		}
		free(path);
	}
	free(key);
	free(data_len);
	free(file_name);
    return 1;
}

int put_file(SSL *ssl, char* buf, char* owner)
{
    int r;
	char* output;
	int success;

	int i=0, slash=0;
	while(i<strlen(&buf[4])) {
		if(buf[4+i] == '/') slash = i+1;
		i++;
	}
	char* file_name = (char*) calloc(1, strlen(&buf[4+slash]));
	strncat(file_name, &buf[4+slash], strlen(&buf[4+slash])-1);

	char* argv[2];
	argv[0]=file_name;
	argv[1]=owner;
	if(verify_meta(2, argv, 0)<2){
		output = "Error: File Exists (Permission denied).\n";
		success = 0;
	}
	else{
		output = "Success: Send data.\n";
		success = 1;
	}
	send_data(ssl, output);

	if(success){
		char* path = (char*) calloc(1, 50+strlen(buf));
		strcat(path, "../FileSystem/files/");
		strcat(path, file_name);
		FILE *file = fopen(path, "w");
		char* buf = 0;
		char* response = 0;
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
		char* hash_result = 0;
		char* encrypt_result = 0;
		getSHA1(response, &hash_result);
		int enc_len = encryptFile(response, hash_result, &encrypt_result);
		fwrite(encrypt_result, enc_len+1, 1, file);
		fclose(file);
		char *data_len = (char*) calloc(1,20);
		sprintf(data_len, "%d", enc_len);

		unsigned char* RSA_result = 0;
		int rsa_len = RSACrypt((unsigned char*)hash_result, 1, PUBFILE, 0, &RSA_result);
		free(hash_result);
		hash_result = (char*) calloc(1, rsa_len*2 + 1);
		int i;
		for(i=0; i< rsa_len; i++) {
			char hex_print[2];
			sprintf(hex_print, "%02x", RSA_result[i]);
			strcat(hash_result, hex_print);
		}

		write_meta(file_name, owner, " 7 1\n", hash_result, data_len, 0);
		free(RSA_result);
		free(hash_result);
		free(encrypt_result);
		free(data_len);
		free(file_name);
		free(path);
		free(buf);
		free(response);
	}

    return 1;
}

int send_data(SSL *ssl, char* output)
{
    int request_len=strlen(output);
    int r=SSL_write(ssl,output,request_len);		
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
	}
	return 1;
}

int rec_data(char* command, SSL *ssl)
{
    int r,len;
	char buf[BUFSIZZ];
    BIO *io,*ssl_bio;
    
    io=BIO_new(BIO_f_buffer());
    ssl_bio=BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio,ssl,BIO_NOCLOSE);
    BIO_push(io,ssl_bio);
	len = -1;

    while(1){
      r=BIO_gets(io,buf,BUFSIZZ-1);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
	      strcat(command, buf);
          len=r;
          break;
        default:
          berr_exit("SSL read problem");
      }

		if(SSL_pending(ssl)<=0) break;
    }
	return len;
}

void close_SSL(SSL *ssl, int s)
{
    int r=SSL_shutdown(ssl);
    if(!r){
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }
      
    switch(r){  
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }

    SSL_free(ssl);
    close(s);
}

