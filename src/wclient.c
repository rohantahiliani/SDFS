#include "common.h"
#include "client.h"

static char *host=HOST;
static int port=PORT;
    
int main(int argc, char** argv)
{
	char* CERTFILE;
	char* KEYFILE;
	char* PASSWORD;

	if(argc<3) {
		printf("Usage: ./wclient cert-file key-file.\n");
		exit(0);
	}
	else {
		CERTFILE = argv[1];
		KEYFILE = argv[2];
		const char* PROMPT = "Enter password for Key file: ";
		PASSWORD = getpass(PROMPT);
	}

    SSL_CTX *ctx=initialize_ctx(CERTFILE,KEYFILE,PASSWORD);
	free(PASSWORD);
    SSL *ssl=0;
	FILE *file;
	char* file_name = 0;
	char* command = (char*)malloc(500);
    int sock=-1;

	while(1){
		memset((void*)command, 0, 500);
		printf("Enter command: ");
		command = fgets(command, 500, stdin);
/* START SESSION */
		if(starts_with(command, "START")){
printf("%ld\n", time(0));
			ssl=SSL_new(ctx);
			sock=tcp_connect(host,port);
			if(connect_SSL(ssl, ctx, sock)<=0) {
				printf("Connection closed.\n");
				memset((void*)command, 0, 500);
				strcpy(command, "END");
				send_data(ssl, command);
				close_SSL(ssl, sock);
				free(command);
				destroy_ctx(ctx);
				exit(0);
			}
			else {
				char* response = 0;
				rec_data(ssl, &response);
				if(starts_with(response, "Revoked")) {
					printf("Certificate Revoked by Server.\n");
					close_SSL(ssl, sock);
					free(command);
					free(response);
					destroy_ctx(ctx);
					exit(0);
				}
				free(response);
			}
printf("%ld\n", time(0));
		}
		else{
			if(ssl == 0){
				printf("Session not established. Please use the START command to establish a session.\n");
			}

/* SEND FILE TO SERVER */

			else if(starts_with(command, "PUT")){
printf("%ld\n", time(0));
				char* file_data = 0;
				if(strlen(command)<7){
					printf("	Incorrect syntax. Use: PUT <file_name>\n");
					continue;
				}
				else{
					file_name = (char*) calloc(1,strlen(&command[4]));
					strncat(file_name, &command[4], strlen(&command[4])-1);
					file = fopen(file_name, "r");
					if(file==NULL){
						printf("	File does not exist.\n");
						free(file_name);
						continue;
					}
					else{
						struct stat fstat;
						stat(file_name, &fstat);
						file_data = (char*) calloc(1, fstat.st_size+4);
						fread(file_data, fstat.st_size, 1, file);
						fclose(file);
					}
				}
				send_data(ssl, command);
				char* response = 0;
				rec_data(ssl, &response);
				if(!starts_with(response, "Error") && starts_with(response, "Success")){
					send_data(ssl, file_data);
				}
				else printf("%s\n",response);
				printf("	File Created At Server: %s\n", file_name);
				free(file_name);
				free(file_data);
				free(response);
printf("%ld\n", time(0));
			}

/* GET FILE FROM SERVER */

			else if(starts_with(command, "GET")){
printf("%ld\n", time(0));
				if(strlen(command)<7){
					printf("	Incorrect syntax. Use: GET <file_name>\n");
					continue;
				}
				else{
					file_name = (char*) calloc(1,strlen(&command[4])+10);
					strcat(file_name, "files/");
					strncat(file_name, &command[4], strlen(&command[4])-1);
				}
				send_data(ssl, command);
				char* response = 0;
				rec_data(ssl, &response);
				if(!starts_with(response, "Error")){
					file = fopen(file_name, "w");
					fwrite(response, strlen(response), 1, file);
					fclose(file);
					printf("	File Created: %s\n", file_name);
				}
				else printf("%s\n", response);
				free(file_name);
				free(response);
printf("%ld\n", time(0));
			}

/* DELEGATE PERMISSION TO USER WITH/WITHOUT PROPOGATE */

			else if(starts_with(command, "DELEGATE")){
				char* file_name = (char*) calloc(1, 512);
				char* user = (char*) calloc(1, 512);
				long time_allowed;

				if(sscanf(&command[9], "%s %s %ld", file_name, user, &time_allowed)!=3) {
					printf("Invalid syntax. Use: DELEGATE(*) file_name user_name time_in_seconds.\n");
					continue;
				}
				send_data(ssl, command);
				free(file_name);
				free(user);
				char* response = 0;
				rec_data(ssl, &response);
				printf("%s\n", response);
				free(response);
			}

/* END SESSION */

			else if(starts_with(command, "END")){
				send_data(ssl, command);
				close_SSL(ssl, sock);
				break;
			}

/* INVALID COMMAND */

			else{
				printf("Invalid command\n");
			}
		}
	}
	free(command);
    destroy_ctx(ctx);
    exit(0);
}

