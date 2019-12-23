#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "http_util.h"

bool get_param(const uint8_t* http, const char* param, char** out, int* out_len){
	int i = 0;
	int len = strlen(param);
	while(true){
		if(!memcmp((uint8_t*)http + i, param, len)){
			*out = (char*)((uint8_t*)http + i + strlen(param) + 2);	// +2 : (due to ': ')
			int j = 0;
			while(memcmp((uint8_t*)http + i + strlen(param) + 2 + j, "\x0d\x0a", 2)) { j++; }
			*out_len = j;
			return true;
		}
		else if(!memcmp((uint8_t*)http + i, "\x0d\x0a\x0d\x0a", 4)){
			// end of http packet
			return false;
		}
		else{
			i++;
		}
	}
}

bool is_http(const uint8_t* tcp){
	char* chk_list[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

	for(int i = 0; i < 6; i++){
		if(!memcmp(tcp, chk_list[i], strlen(chk_list[i]))) return true;
	}
	return false;
}
