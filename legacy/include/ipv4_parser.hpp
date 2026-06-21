#pragma once

void print_ethernet_header(const unsigned char *buffer, int size);
void print_ipv4_header(const unsigned char *buffer, int size);

void parse_icmpv4_packet(const unsigned char *buffer, int size);
void parse_tcp_ipv4_packet(const unsigned char *buffer, int size);
void parse_udp_ipv4_packet(const unsigned char *buffer, int size);

