#include <stdio.h> // for perror
#include <stdlib.h>
#include <string.h> // for memset
#include <unistd.h> // for close
#include <arpa/inet.h> // for htons
#include <netinet/in.h> // for sockaddr_in
#include <sys/socket.h> // for socket

#include <thread>

#include "pcap_handle.h"

void get_and_print(int sockfd){
	const static int BUFSIZE = 1024;
	char buf[BUFSIZE];

	while(true){
		ssize_t received = recv(sockfd, buf, BUFSIZE - 1, 0);
		if (received == 0 || received == -1) {
			perror("recv failed");
			exit(0);
		}
		buf[received] = '\0';
		printf("%s\n", buf);
	}

}

void usage() {
	printf("syntax : echo_client <host> <port>\n");
	printf("sample : echo_client 127.0.0.1 1234\n");
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	uint32_t server_ip;
	str_to_ip(argv[1], &server_ip);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));
	addr.sin_addr.s_addr = htonl(server_ip);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("connect failed");
		return -1;
	}
	printf("connected\n");

	thread print_thread(get_and_print, sockfd);
	print_thread.detach();

	while (true) {
		const static int BUFSIZE = 1024;
		char buf[BUFSIZE];

		int len = read(0, buf, BUFSIZE - 1);
		if(buf[len-1] == '\n') buf[len-1] = '\0';
		if (strcmp(buf, "quit") == 0) break;

		ssize_t sent = send(sockfd, buf, strlen(buf), 0);
		if (sent == 0) {
			perror("send failed");
			break;
		}
	}

	close(sockfd);
}
