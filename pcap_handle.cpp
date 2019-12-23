#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <vector>
#include <map>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pcap_handle.h"

using namespace std;

// int domain_to_ip(char* domain, uint32_t* out){
// 	// https://www.joinc.co.kr/w/man/3/getaddrinfo
// 	struct addrinfo hints;
//     struct addrinfo *result, *rp;
//     struct sockaddr_in *sin;
//     struct sockaddr_in6 *sin6;
//     int *listen_fd;
//     int listen_fd_num=0;

//     char buf[80] = {0x00,};
//     int i = 0;

//     memset(&hints, 0x00, sizeof(struct addrinfo));

//     hints.ai_flags = AI_PASSIVE;
//     hints.ai_family = AF_UNSPEC;
//     hints.ai_socktype = SOCK_STREAM;

//     if(getaddrinfo(NULL, domain, &hints, &result) != 0 )
//     {
//             perror("getaddrinfo");
//             return 1;
//     }

//     for(rp = result ; rp != NULL; rp = rp->ai_next)
//     {
//             listen_fd_num++;
//     }
//     listen_fd = (int*)malloc(sizeof(int)*listen_fd_num);

//     for(rp = result, i=0 ; rp != NULL; rp = rp->ai_next, i++)
//     {
//             if(rp->ai_family == AF_INET)
//             {
//                     sin = (void *)rp->ai_addr;
//                     inet_ntop(rp->ai_family, &sin->sin_addr, buf, sizeof(buf));
//                     printf("<bind 정보 %d %d %s>\n", rp->ai_protocol, rp->ai_socktype, buf);
//             }
//             else if(rp->ai_family == AF_INET6)
//             {
//                     sin6 = (void *)rp->ai_addr;
//                     inet_ntop(rp->ai_family, &sin6->sin6_addr, buf, sizeof(buf));
//                     printf("<bind 정보 %d %d %s>\n", rp->ai_protocol, rp->ai_socktype, buf);
//             }
//             if((listen_fd[i] = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0)
//             {
//                     printf("Socket Create Error\n");
//             }
//             if(rp->ai_family == AF_INET6)
//             {
//                     int opt = 1;
//                     setsockopt(listen_fd[i], IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof(opt));
//             }

//             if(bind(listen_fd[i], rp->ai_addr, rp->ai_addrlen) != 0)
//             {
//                     if(errno != EADDRINUSE);
//                     {
//                             perror("bind error\n");
//                             return 1;
//                     }
//             }
//             if(listen(listen_fd[i], 5) != 0)
//             {
//                     perror("listen error\n");
//                     return 1;
//             }
//     }
//     freeaddrinfo(result);
//     return 1;
// }

void print_MAC(const char* label, MAC mac){
	printf("%s : %02X:%02X:%02X:%02X:%02X:%02X\n", label,
		mac.i[0], mac.i[1], mac.i[2], mac.i[3], mac.i[4], mac.i[5]);
}

void print_IP(const char* label, uint32_t ip){
	printf("%s : %d.%d.%d.%d\n", label,
		(ip & 0xFF000000) >> 24,
		(ip & 0x00FF0000) >> 16,
		(ip & 0x0000FF00) >> 8,
		(ip & 0x000000FF));
}

void str_to_ip(char* ip_str, uint32_t* out){
	int i, st;
	int j = -1;
	uint8_t ip_arr[4];
	for(i = 0; i < 4; i++){
		st = ++j;
		for(; ip_str[j] != '.' && ip_str[j] != '\x00'; j++);
		ip_str[j] = '\x00';
		ip_arr[3 - i] = atoi(ip_str + st);
	}
	memcpy(out, ip_arr, 4);
}

void print_packet(const char* des, const u_char* packet, int len){
	printf("\n[%s] packet", des);
	for(int i = 0; i < len; i++){
		if(i % 16 == 0) printf("\n");
		printf("%02x ", *(packet + i));
	}
	printf("\n");
}
