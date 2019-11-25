#!/bin/bash
for i in {1..5}; do echo "\\e[${i}m"; done

for((i=1;i<=10;i+=2)); do echo "Welcome $i times"; done

if [ -f "/etc/passwd" ]; then echo "The file exists"; fi

if [ ! -f "/etc/bebebe" ]; then echo "The file does not exist"; fi
