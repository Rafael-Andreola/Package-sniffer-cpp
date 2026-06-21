#pragma once

#include <stdint.h>

void print_ipv6_header(const unsigned char *buffer, int size);

// Localiza o protocolo de transporte após o cabeçalho IPv6 base e os
// cabeçalhos de extensão suportados. O deslocamento retorna TCP, UDP ou ICMPv6.
bool find_ipv6_transport(const unsigned char *buffer, int size, int *offset, uint8_t *next_header);

void parse_icmpv6_packet(const unsigned char *buffer, int size, int transport_offset);
void parse_tcp_ipv6_packet(const unsigned char *buffer, int size, int transport_offset);
void parse_udp_ipv6_packet(const unsigned char *buffer, int size, int transport_offset);
