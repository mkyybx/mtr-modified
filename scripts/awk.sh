#!/bin/sh
wc < $1 | awk '{print $1-2}'
awk 'NR > 2 {print $2 "\t" $8}' $1 | sed 's/AS//g' | sed 's/?/0/g' #The input of mtr sample


