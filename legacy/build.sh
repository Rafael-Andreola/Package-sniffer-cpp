#! /bin/bash

set -xe

g++ -o sniffer ./src/raw_sniffer.cpp -g -std=c++17
