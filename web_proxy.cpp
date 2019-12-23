#include <stdio.h> // for perror
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <string.h> // for memset
#include <unistd.h> // for close
#include <arpa/inet.h> // for htons
#include <netinet/in.h> // for sockaddr_in
#include <sys/socket.h> // for socket
#include <sys/types.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>   


#include <vector>
#include <thread>
#include <mutex>

#include "pcap_handle.h"
#include "http_util.h"
#include "ssl_util.h"

#define BUFSIZE 1024
#define FAIL -1

using namespace std;

union End {
	int fd;
	SSL* ssl;
};

enum proxy_type {
	http = 80,
	https = 443
};

uint32_t my_recv(End e, char* buf, int size, proxy_type type){
	if(type == http)
		return recv(e.fd, buf, size, 0);
	else
		return SSL_read(e.ssl, buf, size);
}

uint32_t my_send(End e, char* buf, int size, proxy_type type){
	if(type == http)
		return send(e.fd, buf, size, 0);
	else
		return SSL_write(e.ssl, buf, size);
}

int web_connect(uint32_t server_ip, proxy_type type, End* server){
	
	// making server connection
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(type);
	addr.sin_addr.s_addr = htonl(server_ip);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("connect failed");
		return -1;
	}

	if(type == http)	server->fd = sockfd;
	else{	//type == https
		SSL_CTX *ctx;
	    int server_fd;
	    SSL *ssl;
	    char buf[1024];
	    char acClientRequest[1024] = {0};
	    int bytes;
	    SSL_library_init();
	    ctx = InitCTX();
	    server_fd = sockfd;
	    ssl = SSL_new(ctx);      /* create new SSL connection state */
	    SSL_set_fd(ssl, server_fd);    /* attach the socket descriptor */
	    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
	    	return -1;
	    server->ssl = ssl;
	}

	return 0;
}

void proxy_response_thread(End client, End server, proxy_type type){

	char buf[BUFSIZE];

	while (true) {

		ssize_t received = my_recv(server, buf, BUFSIZE - 1, type);
		if (received == 0 || received == -1) {
			perror("recv failed");
			break;
		}
		buf[received] = '\0';

		print_packet("response", (u_char*)buf, 32);

		ssize_t sent = my_send(client, buf, received, type);
		if (sent == 0) {
			perror("send failed");
			break;
		}
	}
}

int proxy_request_thread(End client, proxy_type type){
	End server;

	char buf[BUFSIZE];

	ssize_t received = my_recv(client, buf, sizeof(buf), type);
	buf[received] = '\0';

	if(!is_http((uint8_t*)buf)) return -1;

	char* host;
	int host_len;
	get_param((uint8_t*)buf, "Host", &host, &host_len);
	host[host_len] = '\0';

	// domain to ip
	//http://forum.falinux.com/zbxe/index.php?mid=C_LIB&document_srl=518686
    struct hostent *host_entry;

    host_entry = gethostbyname(host);
    
    uint32_t server_ip;
	memcpy(&server_ip, (struct in_addr*)host_entry->h_addr_list[0], 4);
	server_ip = ntohl(server_ip);

	web_connect(server_ip, type, &server);
	printf("connected\n");

	thread run_thread(proxy_response_thread, client, server, type);
	run_thread.detach();

	while (true) {

		ssize_t sent = my_send(server, buf, received, type);
		if (sent == 0) {
			perror("send failed");
			break;
		}

		print_packet("send to s", (u_char*)buf, 32);

		received = my_recv(client, buf, BUFSIZE - 1, type);
		if (received == 0 || received == -1) {
			perror("recv failed");
			break;
		}
		buf[received] = '\0';
	}
}

int https_proxy(int port){
	SSL_CTX *ctx;
    int server;

    // Initialize the SSL library
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "test.com.crt", "test.com.key"); /* load certs */
    server = OpenListener(port);    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client_fd = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client_fd);      /* set connection socket to SSL state */
        SSL_accept(ssl);

        End client;
        client.ssl = ssl;

        thread run_thread(proxy_request_thread, client, https);	/* service connection */
        run_thread.detach();
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}

int http_proxy(int port) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = bind(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("bind failed");
		return -1;
	}

	res = listen(sockfd, 2);
	if (res == -1) {
		perror("listen failed");
		return -1;
	}

	while (true) {
		struct sockaddr_in addr;
		socklen_t clientlen = sizeof(sockaddr);
		int childfd = accept(sockfd, reinterpret_cast<struct sockaddr*>(&addr), &clientlen);
		if (childfd < 0) {
			perror("ERROR on accept");
			break;
		}

		End client;
		client.fd = childfd;

		thread run_thread(proxy_request_thread, client, http);
		run_thread.detach();
	}
	
	close(sockfd);
}

void usage() {
	printf("syntax : web_proxy <tcp port> <ssl port>\n");
	printf("sample : web_proxy 8080 4433\n");
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	http_proxy(atoi(argv[1]));
	https_proxy(atoi(argv[2]));

}
