//
// Created by root on 18-8-26.
//

#ifndef MTR_TCP_H
#define MTR_TCP_H

#include <stdint.h>

extern int sendData(int stream_socket, const char* ipaddr, uint16_t port, uint8_t ttl, uint8_t* payload, int payload_len);
extern int initTCP(const char* ipaddr, uint16_t port);
#endif //MTR_TCP_H
