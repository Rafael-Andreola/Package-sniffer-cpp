#! /bin/bash

set -xe

g++ -o sniffer ./cpp/raw_sniffer.cpp -g -std=c++17
