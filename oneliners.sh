#!/bin/bash

#Have an execution go in the background and still be active
myprogram > ~/program.log 2>&1 &

#One liner for loops
for i in {1..5}; do echo "\\e[${i}m"; done

for((i=1;i<=10;i+=2)); do echo "Welcome $i times"; done

#Check if a file exists or not
if [ -f "/etc/passwd" ]; then echo "The file exists"; fi

if [ ! -f "/etc/bebebe" ]; then echo "The file does not exist"; fi
