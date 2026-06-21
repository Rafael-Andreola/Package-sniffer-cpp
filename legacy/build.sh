#! /bin/bash

set -xe

g++ -o sniffer ./cpp/*.cpp -I./include -g -std=c++17
