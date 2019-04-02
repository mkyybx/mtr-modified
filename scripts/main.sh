#!/bin/sh
g++ main.cpp
./awk.sh $1 | ./a.out 
