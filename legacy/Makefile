CXX ?= g++
CXXFLAGS ?= -g -std=c++17
CPPFLAGS ?= -I./include
WARNFLAGS ?= -Wall -Wextra

SRC := $(wildcard ./cpp/*.cpp)
BIN := ./sniffer
IFACE ?= wlp0s20f3
PROTO ?= tcp

.PHONY: all build check usage run run-proto run-tcp run-udp run-icmp run-ipv6 clean

all: build

build:
	$(CXX) -o $(BIN) $(SRC) $(CPPFLAGS) $(CXXFLAGS)

check:
	$(CXX) -o /tmp/sniffer-check $(SRC) $(CPPFLAGS) $(CXXFLAGS) $(WARNFLAGS)

usage: build
	-$(BIN)

run: build
	sudo $(BIN) $(IFACE)

run-proto: build
	sudo $(BIN) $(IFACE) --proto $(PROTO)

run-tcp: build
	sudo $(BIN) $(IFACE) --proto tcp

run-udp: build
	sudo $(BIN) $(IFACE) --proto udp

run-icmp: build
	sudo $(BIN) $(IFACE) --proto icmp

run-ipv6: build
	sudo $(BIN) $(IFACE) --proto ipv6

clean:
	rm -f $(BIN) /tmp/sniffer-check sniff_logger.txt
