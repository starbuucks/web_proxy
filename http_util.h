#pragma once

#include <stdint.h>

using namespace std;

bool get_param(const uint8_t* http, const char* param, char** out, int* out_len);
bool is_http(const uint8_t* tcp);
