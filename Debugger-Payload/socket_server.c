#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define RED   "\x1B[31m"
#define GREEN   "\x1B[32m"
#define YELLOW   "\x1B[33m"
#define BLUE   "\x1B[34m"
#define MAGENT   "\x1B[35m"
#define CYAN   "\x1B[36m"
#define WHITE   "\x1B[37m"
#define RESET "\x1B[0m"

void sigchld_handler(int s)
{
	while(wait(NULL) > 0);
}

void clean_buffer(char * buffer, int len)
{
	for(int i = 0; i < len; i++)
	{
		buffer[i] = 0;
	}
}

int main(int argc, char const *argv[])
{
	int sockfd, new_sockfd, addrlen, bytes_readed, i;
	char mens_serv[100];
	char comand[100];
	/*FILE * chat;*/
	/*Socket*/
	struct sockaddr_in my_addr, remote_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd == -1)
	{
		perror("socket");
		exit(1);
	}

	/*Asignacion de valores al tipo de socket*/
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = inet_addr("192.168.1.38");
	my_addr.sin_port = htons(4321);
	memset(&(my_addr.sin_zero), '\0', 8);
	/*Funcion bind*/
	if(bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1)
	{
		perror("bind");
		exit(1);
	}
	/*Se pone a escuchar*/
	if(listen(sockfd, 5) == -1)
	{
		perror("listen");
		exit(1);
	}

	printf("%sj0lama %sPS4 Real Time Editor\n",GREEN, YELLOW);

	addrlen = sizeof(struct sockaddr);
	new_sockfd = accept(sockfd, (struct sockaddr *)&remote_addr, &addrlen);
	if(new_sockfd == -1)
	{
		perror("accept");
		exit(1);
	}
	printf("%sNew PS4: %s%s%s\n", GREEN, BLUE, inet_ntoa(remote_addr.sin_addr), RESET);
	clean_buffer(comand, 100);



	recv(new_sockfd, (void *) &mens_serv, 100, 0);
	printf("%sPS4[%s]%s: %s", BLUE, inet_ntoa(remote_addr.sin_addr), RESET, mens_serv);

	while(strcmp(comand, "[+] Payload ready!") != 0)
	{
		clean_buffer(mens_serv, 100);
		printf("\nProcess name: ");
		fgets(comand, 100, stdin);
		send(new_sockfd, comand, 100, 0);
		bytes_readed = recv(new_sockfd, (void *) &mens_serv, 100, 0);
		if(bytes_readed == 0)
		{
			printf("Unexpected error\n");
		}
		else
		{
			if(strcmp(mens_serv, "[+] Payload ready!") == 0)
			{
				printf("%sPS4[%s]%s: %s", BLUE, inet_ntoa(remote_addr.sin_addr), RESET, mens_serv);
				break;
			}
			else
				printf("%sPS4[%s]%s: %s", BLUE, inet_ntoa(remote_addr.sin_addr), RESET, mens_serv);
		}
	}

	while(1)
	{
		clean_buffer(comand, 100);
		printf("\n%s>%s", YELLOW, RESET);
		fgets(comand, 100, stdin);
		if(comand[0] == 'h' && comand[1] == 'e' && comand[2] == 'l' && comand[3] == 'p')
		{
			printf("Read memory: r 0xOffset\nWrite memory: w 0xOffset 0xValue\nFind: u 0xOffset 0xValue(Only looks for between Offset and Offset+0x1000)\nFind Prev: d 0xOffset 0xValue (Only looks for between Offset and Offset-0x1000)\n New process: p Process_Name");
		}
		else
		{
			send(new_sockfd, comand, 100, 0);
			bytes_readed = recv(new_sockfd, (void *) &mens_serv, 100, 0);
			if(bytes_readed == 0)
			{
				printf("%s[%s] disconnected%s\n", RED, inet_ntoa(remote_addr.sin_addr), RESET);
				break;
			}
			printf("%sPS4[%s]%s: %s", BLUE, inet_ntoa(remote_addr.sin_addr), RESET, mens_serv);
		}
	}
	close(new_sockfd);

	printf("Closing server...\n");
	return 0;
}